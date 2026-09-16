rule sig_20160527_25f6ce10bb494efc11e49b1dbc435a03 {
  meta:
    description = "datamaliciousorder - file 20160527_25f6ce10bb494efc11e49b1dbc435a03.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79b73229efd0c91a7290e7f12e1b91cf6ea4c832838ff83d1b1fd4650fa4d372"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aoXQbPDv4G0.length;i++)if(i%2==0)x.push(aoXQbPDv4G0[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}