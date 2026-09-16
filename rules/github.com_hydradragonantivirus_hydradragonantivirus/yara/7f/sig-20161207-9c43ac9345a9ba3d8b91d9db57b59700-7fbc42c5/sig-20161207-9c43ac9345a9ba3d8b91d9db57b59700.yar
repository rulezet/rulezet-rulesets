rule sig_20161207_9c43ac9345a9ba3d8b91d9db57b59700 {
  meta:
    description = "datamaliciousorder - file 20161207_9c43ac9345a9ba3d8b91d9db57b59700.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a23eed9d887a9bf4f859fa14c83334f4681d9298678d5f842295abbcb49a049a"

  strings:
    $s1 = "var vGAl3 = new Function(\"vAn3\", '{return vAn3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMb4 = new Function(\"vAn3" ascii
    $s2 = "new Date();vOn7[\"setUTCFullYear\"](\"2003\");if (vOn7.getUTCFullYear().toString(10) == \"2003\") {var vFHi5 = vAn3.split(\"####" ascii
    $s3 = "var vGAl3 = new Function(\"vAn3\", '{return vAn3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMb4 = new Function(\"vAn3" ascii
    $s4 = "urn vFHi5.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}