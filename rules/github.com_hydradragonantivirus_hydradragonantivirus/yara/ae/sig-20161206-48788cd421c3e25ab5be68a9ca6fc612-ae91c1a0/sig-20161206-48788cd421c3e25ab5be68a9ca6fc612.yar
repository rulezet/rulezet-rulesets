rule sig_20161206_48788cd421c3e25ab5be68a9ca6fc612 {
  meta:
    description = "datamaliciousorder - file 20161206_48788cd421c3e25ab5be68a9ca6fc612.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a91c24817c77017078b2f8d9337bec419e431b1bc905af540acbbcca143a0d16"

  strings:
    $s1 = "var vLVi4 = new Function(\"s\", '{var vAz1 = new Date();vAz1[\"setUTCFullYear\"](\"2003\");if (vAz1.getUTCFullYear().toString(10" ascii
    $s2 = "var vLVi4 = new Function(\"s\", '{var vAz1 = new Date();vAz1[\"setUTCFullYear\"](\"2003\");if (vAz1.getUTCFullYear().toString(10" ascii
    $s3 = "2003\") {var vAm4 = s.split(\"##\"); return vAm4.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vAc9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}