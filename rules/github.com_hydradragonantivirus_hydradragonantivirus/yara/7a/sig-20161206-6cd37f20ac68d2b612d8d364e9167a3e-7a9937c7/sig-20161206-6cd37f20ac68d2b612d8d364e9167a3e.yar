rule sig_20161206_6cd37f20ac68d2b612d8d364e9167a3e {
  meta:
    description = "datamaliciousorder - file 20161206_6cd37f20ac68d2b612d8d364e9167a3e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "abf9aff7175772fb2e1aee472dcda1bf6bb661b2ef8cefaf09c22b193a2af812"

  strings:
    $s1 = "var vWy5 = new Function(\"s\", '{var vDBv2 = new Date();vDBv2[\"setUTCFullYear\"](\"2003\");if (vDBv2.getUTCFullYear().toString(" ascii
    $s2 = "var vWy5 = new Function(\"s\", '{var vDBv2 = new Date();vDBv2[\"setUTCFullYear\"](\"2003\");if (vDBv2.getUTCFullYear().toString(" ascii
    $s3 = "function vFx4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = " \"2003\") {var vCYc2 = s.split(\"##\"); return vCYc2.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}