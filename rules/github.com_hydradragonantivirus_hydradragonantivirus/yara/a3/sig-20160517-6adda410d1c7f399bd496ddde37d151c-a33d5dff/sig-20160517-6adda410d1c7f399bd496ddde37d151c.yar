rule sig_20160517_6adda410d1c7f399bd496ddde37d151c {
  meta:
    description = "datamaliciousorder - file 20160517_6adda410d1c7f399bd496ddde37d151c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "985526b21514d7a7e58b982e993381a020473850e85be811631d72d118566ee1"

  strings:
    $s1 = "var vrm='vqh1tnaucrnfrpkdgv gzdo3lwxehtkl4ne3faojkiqy4orqfalbbwbytwehmclfcxac31qh=kazlp\\'lms1dtrytoacipxmxnikjoriertgifejmbzutn" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}