rule sig_20161208_01675dba94080e8580ac7df5c837380e {
  meta:
    description = "datamaliciousorder - file 20161208_01675dba94080e8580ac7df5c837380e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4088adda902acb00d48ad006a125d08ffa6ed248b244f93feb84bc7b7c93aa95"

  strings:
    $s1 = "var vUu9 = new Function(\"vJj3\", '{return vJj3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vESl4 = new Function(\"vJj3" ascii
    $s2 = "new Date();vOb2[\"setUTC\"+\"FullYear\"](\"2003\");if (vOb2.getUTCFullYear().toString(10) == \"2003\") {var vPZl4 = vJj3.split(" ascii
    $s3 = "return vPZl4.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vUu9 = new Function(\"vJj3\", '{return vJj3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vESl4 = new Function(\"vJj3" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}