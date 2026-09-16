rule infected_07_13_18_savoie_index {
  meta:
    description = "savoie - file index.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-07-13"
    hash1       = "4fa56221e38a08c4ad68878580d437d2bef8c0cc72d8173e019ade77301139f2"

  strings:
    $s1 = "$uploadfile = $_POST['path'].$_FILES['uploadfile']['name'];" fullword ascii
    $s2 = "if (move_uploaded_file($_FILES['uploadfile']['tmp_name'], $uploadfile))" fullword ascii
    $s3 = "fwrite($fp, $_POST['uploadfile']);" fullword ascii
    $s4 = "else {echo $_FILES['uploadfile']['error'];}" fullword ascii
    $s5 = "if ($_POST['upload']=='1'){" fullword ascii
    $s6 = "if (isset($_POST['upload'])){" fullword ascii
    $s7 = "if ($_POST['upload']=='2'){" fullword ascii
    $s8 = "$fp=fopen($_POST['path'],'a');  " fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 1KB and
      (all of them)
    ) or (all of them)
}