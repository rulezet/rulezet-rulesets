rule sig_20161206_de8f40e638ad47a3a597a04284c1b8b8 {
  meta:
    description = "datamaliciousorder - file 20161206_de8f40e638ad47a3a597a04284c1b8b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7dfb444050074e460c0200550245ab22a3deaf18c08046fe6dcd7281d35df3e"

  strings:
    $s1 = "var vFx4 = new Function(\"s\", '{var vWe5 = new Date();vWe5[\"setUTCFullYear\"](\"2003\");if (vWe5.getUTCFullYear().toString(10)" ascii
    $s2 = "var vFx4 = new Function(\"s\", '{var vWe5 = new Date();vWe5[\"setUTCFullYear\"](\"2003\");if (vWe5.getUTCFullYear().toString(10)" ascii
    $s3 = "function vBTh7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "003\") {var vWp4 = s.split(\"##\"); return vWp4.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}