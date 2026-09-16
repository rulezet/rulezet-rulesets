rule sig_20161208_046a274742a451f6a76166831086b9cd {
  meta:
    description = "datamaliciousorder - file 20161208_046a274742a451f6a76166831086b9cd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "078ffade8dfd52665b6d3be95552d607baf77718d866e4587e360a8e1b0fe772"

  strings:
    $s1 = "var vFWb4 = new Function(\"vLg2\", '{return vLg2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vAVj6 = new Function(\"vLg2" ascii
    $s2 = "= new Date();vKJn2[\"setUTC\"+\"FullYear\"](\"2003\");if (vKJn2.getUTCFullYear().toString(10) == \"2003\") {var vCHh9 = vLg2.spl" ascii
    $s3 = "\"); return vCHh9.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vFWb4 = new Function(\"vLg2\", '{return vLg2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vAVj6 = new Function(\"vLg2" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}