rule sig_20160527_932c4f22a1410c84e3e40ef367de28ef {
  meta:
    description = "datamaliciousorder - file 20160527_932c4f22a1410c84e3e40ef367de28ef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fed144fcd865035e15c5d7b773b3e187d079ffede1cf5e3ca35f0516cce9c24d"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<a5b5stdWO.length;i++)if(i%2==0)x.push(a5b5stdWO[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}