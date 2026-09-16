rule sig_20160527_62d9dc7246f2d6afeb4c2cdad7131f8c {
  meta:
    description = "datamaliciousorder - file 20160527_62d9dc7246f2d6afeb4c2cdad7131f8c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be11d47051ad47255ae7a2fa9c79800893e7ecfda18c8ab9c0f0150e85f36735"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aX8HyZ.length;i++)if(i%2==0)x.push(aX8HyZ[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}