rule sig_20160527_c79038fe326d939cc365d69741c8c303 {
  meta:
    description = "datamaliciousorder - file 20160527_c79038fe326d939cc365d69741c8c303.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09ffa6edb007606e52cc48e6c9433a1f4a6bdc7dd42347c6446be116cd8f156d"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aeLxomvm.length;i++)if(i%2==0)x.push(aeLxomvm[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}