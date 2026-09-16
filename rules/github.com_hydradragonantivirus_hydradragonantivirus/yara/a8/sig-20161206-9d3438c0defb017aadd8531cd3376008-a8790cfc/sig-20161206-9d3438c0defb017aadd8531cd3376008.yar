rule sig_20161206_9d3438c0defb017aadd8531cd3376008 {
  meta:
    description = "datamaliciousorder - file 20161206_9d3438c0defb017aadd8531cd3376008.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "710e7bfd090fff2be5112e801c31e3cdf6760ef22588b12a35aa6105000ccf93"

  strings:
    $s1 = "var vKCh1 = new Function(\"s\", '{var vQMo9 = new Date();vQMo9[\"setUTCFullYear\"](\"2003\");if (vQMo9.getUTCFullYear().toString" ascii
    $s2 = "var vKCh1 = new Function(\"s\", '{var vQMo9 = new Date();vQMo9[\"setUTCFullYear\"](\"2003\");if (vQMo9.getUTCFullYear().toString" ascii
    $s3 = "function vCNj4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "= \"2003\") {var vWd3 = s.split(\"##\"); return vWd3.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}