rule sig_20160530_5d7b2656100483f8159091dce9689e89 {
  meta:
    description = "datamaliciousorder - file 20160530_5d7b2656100483f8159091dce9689e89.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2b75f6c12a024acb1c43eb760c772e543dbc158e3fdbccefed7589111a85f60"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aJ2wrziK.length;i++)if(i%2==0)x.push(aJ2wrziK[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}