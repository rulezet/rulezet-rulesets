rule sig_20160527_27f10d9f65cb0d1fb9134c6cd9d75e88 {
  meta:
    description = "datamaliciousorder - file 20160527_27f10d9f65cb0d1fb9134c6cd9d75e88.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6fecab6e7516ede812f182d854471c61ecc2480416e5d2e71f0eaf99fdc4fe45"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aXS7z5H6RA.length;i++)if(i%2==0)x.push(aXS7z5H6RA[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}