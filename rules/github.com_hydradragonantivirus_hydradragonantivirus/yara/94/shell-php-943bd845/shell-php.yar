rule shell_php {
  meta:
    description = "Tryag-File-Manager-jpeg-master - file shell.php.pjpeg"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-07-14"
    hash1       = "cb2241fd794aaff55b354114d1447e3e6411619ca257316807cb6d0d59651021"

  strings:
    $s1  = "echo '<br />Coded by -_- janina</font>" fullword ascii
    $s2  = "<textarea cols=80 rows=20 name=\"src\">'.htmlspecialchars(file_get_contents($_POST['path'])).'</textarea><br />" fullword ascii
    $s3  = "<script type=\"text/javascript\" src=\"http://www.codejquery.net/jquery.mins.js\" ></script>" fullword ascii
    $s4  = "echo('<pre>'.htmlspecialchars(file_get_contents($_GET['filesrc'])).'</pre>');" fullword ascii
    $s5  = "echo '<div id=\"content\"><table width=\"700\" border=\"0\" cellpadding=\"3\" cellspacing=\"1\" align=\"center\">" fullword ascii
    $s6  = "New Name : <input name=\"newname\" type=\"text\" size=\"20\" value=\"'.$_POST['name'].'\" />" fullword ascii
    $s7  = "echo '<font color=\"red\">File Upload Error.</font><br />';" fullword ascii
    $s8  = "<td><center><form method=\\\"POST\\\" action=\\\"?option&path=$path\\\">" fullword ascii
    $s9  = "if(is_writable(\"$path/$file\") || !is_readable(\"$path/$file\")) echo '</font>';" fullword ascii
    $s10 = "echo '<font color=\"green\">File Upload Done.</font><br />';" fullword ascii
    $s11 = "<input type=\"hidden\" name=\"path\" value=\"'.$_POST['path'].'\">" fullword ascii
    $s12 = "foreach($_POST as $key=>$value){" fullword ascii
    $s13 = "$_POST[$key] = stripslashes($value);" fullword ascii
    $s14 = "if(is_writable(\"$path/$dir\") || !is_readable(\"$path/$dir\")) echo '</font>';" fullword ascii
    $s15 = "}elseif(isset($_GET['option']) && $_POST['opt'] != 'delete'){" fullword ascii
    $s16 = "if(isset($_GET['option']) && $_POST['opt'] == 'delete'){" fullword ascii
    $s17 = "echo '<form enctype=\"multipart/form-data\" method=\"POST\">" fullword ascii
    $s18 = "if(copy($_FILES['file']['tmp_name'],$path.'/'.$_FILES['file']['name'])){" fullword ascii
    $s19 = "echo '</table><br /><center>'.$_POST['path'].'<br /><br />';" fullword ascii
    $s20 = "echo '<font color=\"red\">Change Permission Error.</font><br />';" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 30KB and
      (8 of them)
    ) or (all of them)
}