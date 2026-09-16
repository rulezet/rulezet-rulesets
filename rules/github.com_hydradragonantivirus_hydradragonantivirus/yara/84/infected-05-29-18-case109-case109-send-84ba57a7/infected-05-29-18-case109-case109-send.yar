rule _infected_05_29_18_case109_case109_send {
  meta:
    description = "case109 - file send.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-05-29"
    hash1       = "63f5597336bba04bf274df31ef3efb7d270f5fa10287bb2d14f424729c5eb77e"

  strings:
    $s1  = "$headers .= \"Content-type: text/html; charset=iso-8859-1\\r\\n\";" fullword ascii
    $s2  = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=iso-8859-1\">" fullword ascii
    $s3  = "echo \"* N?mero: $count <b>\".$email[$i].\"</b> <font color=red>ERRO AO ENVIAR</font><br><hr>\";" fullword ascii
    $s4  = "<form action=\"\" method=\"post\" enctype=\"multipart/form-data\" name=\"form1\">" fullword ascii
    $s5  = "echo \"* N?mero: $count <b>\".$email[$i].\"</b> <font color=green>OK</font><br><hr>\";" fullword ascii
    $s6  = "$headers  = \"MIME-Version: 1.0\\r\\n\";" fullword ascii
    $s7  = "$redirectlist = array_unique(explode(\"\\n\",$_POST['redirectlist']));" fullword ascii
    $s8  = "$headers .= \"From: \".$realname.\" <\".$from.\">\\r\\n\";" fullword ascii
    $s9  = "ame\" type=\"text\" class=\"form\" id=\"realname\" style=\"width:48%\" value=\"<?php print $realname; ?>\" size=\"1\" > </td>" fullword ascii
    $s10 = "about it\".md5(rand(0,99999)+rand(0,99999)).\"\\r\\n -->\";" fullword ascii
    $s11 = "if(mail($email[$i], $subject, $messgb, $headers))" fullword ascii
    $s12 = "<table width=\"527\" height=\"511\" border=\"0\" cellpadding=\"0\" cellspacing=\"1\" bgcolor=\"#CCCCCC\" class=\"normal\">" fullword ascii
    $s13 = "<table width=\"100%\"  border=\"0\" cellpadding=\"0\" cellspacing=\"5\" class=\"normal\" height=\"444\">" fullword ascii
    $s14 = "<td height=\"20\" colspan=\"2\" bgcolor=\"#999999\"><span class=\"texto\">C&oacute;digo HTML:</span></td>" fullword ascii
    $s15 = "$to = $_POST['emaillist'];" fullword ascii
    $s16 = "$testa = $_POST['veio'];" fullword ascii
    $s17 = "$realname = $_POST['realname'];" fullword ascii
    $s18 = "$redirect = $redirectlist[$redi].'/'.md5(rand(0,99999)+rand(0,9999));" fullword ascii
    $s19 = "$subject = $_POST['subject'];" fullword ascii
    $s20 = "$message = $_POST['message'];" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 20KB and
      (8 of them)
    ) or (all of them)
}