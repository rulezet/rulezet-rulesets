rule sig_20160302_329e405d29e2e729827c22d75dcb4479 {
  meta:
    description = "datamaliciousorder - file 20160302_329e405d29e2e729827c22d75dcb4479.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19e0ed3d6a93b0fc225c38e52308be52907da7f81cce661dad6dd8d891b7ade2"

  strings:
    $s1 = "            return c((e >>> 10) + 55296) + c((1023 & e) + 56320);" fullword ascii
    $s2 = "var frontierNWe = function(r) {" fullword ascii
    $s3 = "var obtainVQk = function() {" fullword ascii
    $s4 = "    var s = String[\"fr\" + \"om\" + \"C\" + \"ha\" + \"rC\" + \"ode\"];" fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}