rule infected_107_175_218_241_2018_10_14a_shells_wso {
  meta:
    description = "shells - file wso.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-10-28"
    hash1       = "0238dd8da8ae85deb84fe18d1fa5df6673f500554fd4a83bd48d6633f600e8d3"

  strings:
    $s1  = "$cook = suBstR(Md5($_SERVER[\"HTTP_HOST\"]), (int) round(0 + 0 + 0), -154 + 157);" fullword ascii
    $s2  = "for ($_wvlc = StRLEn($_POST[\"s\"]) - (int) round(0.5 + 0.5); $_wvlc >= (int) round(0 + 0); --$_wvlc) {" fullword ascii
    $s3  = "$_dghz += (int) $_POST[\"s\"][$_wvlc] * poW(-5 - -13, StrLEn($_POST[\"s\"]) - $_wvlc - (-37 + 38));" fullword ascii
    $s4  = "echo \"<script>s_=\\\"\\\";</script><form onsubmit=\\\"g(null,null,'\" . uRLeNCOde(STR_roT13($_POST[\"p\"])) . \"',null,this.to" fullword ascii
    $s5  = "echo \"<script>s_=\\\"\\\";</script><form onsubmit=\\\"g(null,null,'\" . urlENCoDE(stR_Rot13($_POST[\"p\"])) . \"',null,this.ch" fullword ascii
    $s6  = "die(\"<form method=post><input type=password name=ps><input type=submit value='>>'></form>\");" fullword ascii
    $s7  = "return strCMP(strtOlOweR($_av[$GLOBALS[\"sort\"][266 - -235 + -501]]), sTRtOLOWer($_wr[$GLOBALS[\"sort\"][-376 + 376]])) * (" fullword ascii
    $s8  = "echo \"<form onsubmit=\\\"g(null,null,'\" . UrlENCoDE(sTR_Rot13($_POST[\"p\"])) . \"',null,rot13(this.name.value));return f" fullword ascii
    $s9  = "echo \"<form onsubmit=\\\"g(null,null,'\" . UrLenCoDE(sTr_Rot13($_POST[\"p\"])) . \"',null,'1'+utoa(this.text.value));retur" fullword ascii
    $s10 = "if (@Preg_mATcH(\"/\" . join(\"|\", $_wejg) . \"/i\", $_SERVER[\"HTTP_USER_AGENT\"])) {" fullword ascii
    $s11 = "} elseif (($_hp & 8257 - 8400 - -8335) == (int) round(2730.6666666667 + 2730.6666666667 + 2730.6666666667)) {" fullword ascii
    $s12 = "$_wvlc .= $_hp & (int) round(4 + 4) ? $_hp & 1318 + -294 ? \"s\" : \"x\" : ($_hp & 1019 + 5 ? \"S\" : \"-\");" fullword ascii
    $s13 = "if ($cwd[stRLeN($cwd) - (int) round(0.33333333333333 + 0.33333333333333 + 0.33333333333333)] != \"/\") {" fullword ascii
    $s14 = "echo \"<html><head><meta http-equiv='Content-Type' content='text/html; charset=\" . $_POST[\"ch\"] . \"'><title>\" . $_SERVER[\"" ascii
    $s15 = "echo hTMLspECiaLcHARs(@fGeTS($_tdtc, 487 - 872 - -1409));" fullword ascii
    $s16 = "HEADer(\"Content-Disposition: attachment; filename=\" . BAsEnAme($_POST[\"p\"]));" fullword ascii
    $s17 = "die(\"<script>g(null,null,\\\"\" . UrLenCODe($_POST[\"s\"]) . \"\\\",null,\\\"\\\")</script>\");" fullword ascii
    $s18 = "echo HtmLsPeCIAlcHArS(@fgETS($_tdtc, 1218 + -194));" fullword ascii
    $s19 = "if (FunctioN_EXisTs(\"get_magic_quotes_gpc\") && FUncTion_ExISTs(\"array_map\") && FunctION_EXIsTs(\"stripslashes\")) {" fullword ascii
    $s20 = "if (!funCTIon_existS(\"posix_getpwuid\") && sTrPOS($GLOBALS[\"disable_functions\"], \"posix_getpwuid\") === false) {" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 90KB and
      (8 of them)
    ) or (all of them)
}