rule sig_20161206_ec1278f944f7c9279da98c012fd614a3 {
  meta:
    description = "datamaliciousorder - file 20161206_ec1278f944f7c9279da98c012fd614a3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b47afe83e2e375a52b7cd1ccedb4305cb1a673d47afd40540eb7bbf79523f070"

  strings:
    $s1 = "var vHu7 = new Function(\"s\", '{var vHAt6 = new Date();vHAt6[\"setUTCFullYear\"](\"2003\");if (vHAt6.getUTCFullYear().toString(" ascii
    $s2 = "var vHu7 = new Function(\"s\", '{var vHAt6 = new Date();vHAt6[\"setUTCFullYear\"](\"2003\");if (vHAt6.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vFYc1 = s.split(\"##\"); return vFYc1.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vROy7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}