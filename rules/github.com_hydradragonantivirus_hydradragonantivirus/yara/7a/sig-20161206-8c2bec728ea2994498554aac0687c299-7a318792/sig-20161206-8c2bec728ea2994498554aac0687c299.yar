rule sig_20161206_8c2bec728ea2994498554aac0687c299 {
  meta:
    description = "datamaliciousorder - file 20161206_8c2bec728ea2994498554aac0687c299.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86faccf01c905a00c409e8c74099f3464218ebbe06a71dd6437acae160815051"

  strings:
    $s1 = "var vPh0 = new Function(\"s\", '{var vAz3 = new Date();vAz3[\"setUTCFullYear\"](\"2003\");if (vAz3.getUTCFullYear().toString(10)" ascii
    $s2 = "var vPh0 = new Function(\"s\", '{var vAz3 = new Date();vAz3[\"setUTCFullYear\"](\"2003\");if (vAz3.getUTCFullYear().toString(10)" ascii
    $s3 = "function vKDk6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "003\") {var vQz4 = s.split(\"##\"); return vQz4.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}