rule sig_20160517_bd9fcfa50e896e3a27d480b22807807a {
  meta:
    description = "datamaliciousorder - file 20160517_bd9fcfa50e896e3a27d480b22807807a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d5a8316bd919bf99d4f1f7d92bad201f57f010ef06be038c823951dc596196e"

  strings:
    $s1 = "var vrm='vqh1tnaucrnfrpkdgv gzdo3lwxehtkl4ne3faojkiqy4orqfalbbwbytwehmclfcxac31qh=kazlp\\'lms1dtrytoacipxmxnikjoriertgifejmbzutn" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}