rule sig_20161208_40dfd27763166e8e4cba52e1b0ae5091 {
  meta:
    description = "datamaliciousorder - file 20161208_40dfd27763166e8e4cba52e1b0ae5091.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "964b53ad47cfb6ce4b6ea8bd1b80eba14d3508b23b4da56177bc86fb6cd659dd"

  strings:
    $s1 = "0 = new Date();vAVh0[\"setUTC\"+\"FullYear\"](\"2003\");if (vAVh0.getUTCFullYear().toString(10) == \"2003\") {var vNFq0 = vMFc0." ascii
    $s2 = "var vNr3 = new Function(\"vMFc0\", '{return vMFc0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCZb5 = new Function(\"vMF" ascii
    $s3 = "###\"); return vNFq0.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vNr3 = new Function(\"vMFc0\", '{return vMFc0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCZb5 = new Function(\"vMF" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}