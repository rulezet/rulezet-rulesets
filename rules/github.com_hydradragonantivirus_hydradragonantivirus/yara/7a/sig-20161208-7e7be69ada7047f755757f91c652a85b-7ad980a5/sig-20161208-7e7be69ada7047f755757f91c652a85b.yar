rule sig_20161208_7e7be69ada7047f755757f91c652a85b {
  meta:
    description = "datamaliciousorder - file 20161208_7e7be69ada7047f755757f91c652a85b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7ce0dcf12298b2d8f9244d77a874406b7b7228db2975301b04631a9778df6cb"

  strings:
    $s1 = "new Date();vZc3[\"setUTC\"+\"FullYear\"](\"2003\");if (vZc3.getUTCFullYear().toString(10) == \"2003\") {var vXAw5 = vUo1.split(" ascii
    $s2 = "var vGi5 = new Function(\"vUo1\", '{return vUo1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vSKr2 = new Function(\"vUo1" ascii
    $s3 = "return vXAw5.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vGi5 = new Function(\"vUo1\", '{return vUo1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vSKr2 = new Function(\"vUo1" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}