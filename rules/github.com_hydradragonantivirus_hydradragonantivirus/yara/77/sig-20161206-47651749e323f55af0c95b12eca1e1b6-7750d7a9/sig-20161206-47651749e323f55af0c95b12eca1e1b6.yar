rule sig_20161206_47651749e323f55af0c95b12eca1e1b6 {
  meta:
    description = "datamaliciousorder - file 20161206_47651749e323f55af0c95b12eca1e1b6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1dca3c3da9b54dae3d8c8214e3b79b2e8734418c5777f55244e7d81ecf35a84c"

  strings:
    $s1 = "var vAq0 = new Function(\"s\", '{var vQy7 = new Date();vQy7[\"setUTCFullYear\"](\"2003\");if (vQy7.getUTCFullYear().toString(10)" ascii
    $s2 = "var vAq0 = new Function(\"s\", '{var vQy7 = new Date();vQy7[\"setUTCFullYear\"](\"2003\");if (vQy7.getUTCFullYear().toString(10)" ascii
    $s3 = "function vKNs1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "003\") {var vIr7 = s.split(\"##\"); return vIr7.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}