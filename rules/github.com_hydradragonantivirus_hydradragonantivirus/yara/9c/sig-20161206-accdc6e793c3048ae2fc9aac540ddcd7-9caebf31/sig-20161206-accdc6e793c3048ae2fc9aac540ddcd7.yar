rule sig_20161206_accdc6e793c3048ae2fc9aac540ddcd7 {
  meta:
    description = "datamaliciousorder - file 20161206_accdc6e793c3048ae2fc9aac540ddcd7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e606f9497255a4a419d8730aeaeaa47bde74dc915d25b0f985e1a19cb97429cb"

  strings:
    $s1 = "var vLy4 = new Function(\"s\", '{var vORw5 = new Date();vORw5[\"setUTCFullYear\"](\"2003\");if (vORw5.getUTCFullYear().toString(" ascii
    $s2 = "var vLy4 = new Function(\"s\", '{var vORw5 = new Date();vORw5[\"setUTCFullYear\"](\"2003\");if (vORw5.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vQd7 = s.split(\"##\"); return vQd7.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vKo7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}