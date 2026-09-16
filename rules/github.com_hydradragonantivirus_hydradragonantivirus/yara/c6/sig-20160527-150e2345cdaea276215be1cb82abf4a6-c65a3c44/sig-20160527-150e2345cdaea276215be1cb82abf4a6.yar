rule sig_20160527_150e2345cdaea276215be1cb82abf4a6 {
  meta:
    description = "datamaliciousorder - file 20160527_150e2345cdaea276215be1cb82abf4a6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56f66087498d7d23d190b7c2b755de33cd16b9fb7c6db64a642f82547edb79b3"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<ak2ByY6j.length;i++)if(i%2==0)x.push(ak2ByY6j[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}