rule sig_20161206_7289730d213cf43cc8294dd40e01799f {
  meta:
    description = "datamaliciousorder - file 20161206_7289730d213cf43cc8294dd40e01799f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc11a5f2061e1be0fbbb4392b2da629cbc5bc850fa102c0ebdabc563875a20dc"

  strings:
    $s1 = "var vFk0 = new Function(\"s\", '{var vOp0 = new Date();vOp0[\"setUTCFullYear\"](\"2003\");if (vOp0.getUTCFullYear().toString(10)" ascii
    $s2 = "var vFk0 = new Function(\"s\", '{var vOp0 = new Date();vOp0[\"setUTCFullYear\"](\"2003\");if (vOp0.getUTCFullYear().toString(10)" ascii
    $s3 = "003\") {var vFp4 = s.split(\"##\"); return vFp4.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vCJh2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}