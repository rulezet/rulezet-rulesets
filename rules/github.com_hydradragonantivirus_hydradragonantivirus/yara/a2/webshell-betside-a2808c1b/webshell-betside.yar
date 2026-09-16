rule webshell_betside {
  meta:
    description = "PHP - file webshell_betside.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-10-11"
    hash1       = "036a95221a016700baf12fb0bbe6d2becfaa26f8e178d4f9d02c72c4b23d6cec"

  strings:
    $s1  = "$O__00OO0O_=base64_decode(\"LTQ2bnFhX2U4OWR5cmJpa2hqZnB3eGN0em1sMnNvdjdndTAzNTE=\");$OO0OO00___=$O__00OO0O_{19}.$O__00OO0O_{12}." ascii
    $s2  = "//header('Content-Type:text/html; charset=utf-8');" fullword ascii
    $s4  = "'Host:\\';$O0O_O0_0O_.=$O0_0_0OO_O;$O__O0O0_0O[]=$O0O_O0_0O_;$O__O0O0_0O[]=${\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\"}[\"\\x4f\\x" ascii
    $s5  = "0O_{29}.$O__00OO0O_{18};header('Content-Type:text/html;charset=utf-8');if(!function_exists('str_ireplace')){function str_ireplac" ascii
    $s6  = "1zMtPFAA==\\');$O0__OOO0_0=\\'http:\\';$O__000_OOO=${\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\"}[\"\\x4f\\x30\\x30\\x4f\\x5f\\x4f" ascii
    $s7  = "x.php\\');echo $O0OOO_0_0_.\\'<div id=\"content\"><textarea rows=\"20%\" cols=\"50%\">\\'.$O_O_0OO0_0.\\'</textarea></div>\\';}e" ascii
    $s8  = "_O0OO0_0_,CURLOPT_USERAGENT,\\'WHR\\');${\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\"}[\"\\x4f\\x5f\\x5f\\x30\\x4f\\x4f\\x30\\x5f\\x4" ascii
    $s9  = "30\\x4f\\x5f\"]($O0_0_O0OO_);$O_O0_OO00_=\"POST $O0_O_O_O00 HTTP/$O0O0__O0O_\\\\r\\\\n\".${\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53" ascii
    $s10 = "O_O0_.\\'/index.php\\');echo $O0_0O_0_OO.\\'<div id=\"content\"><textarea rows=\"20%\" cols=\"50%\">\\'.$O_O_0OO0_0.\\'</textare" ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 70KB and
      (all of them)
    ) or (all of them)
}