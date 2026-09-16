rule sig_20160517_94544c7174c8433dd1f25b93a56431af {
  meta:
    description = "datamaliciousorder - file 20160517_94544c7174c8433dd1f25b93a56431af.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7467964d43aee3d4fba574d7ff65f967f1ba631736df26130fe7ac5f1f03477f"

  strings:
    $s1 = "var jqy='vp4ejlarnuudrloovw hcd3uddpimkjbyynncgyrghnezy1uyhritmrqctmfhmvz2isybgisfbkqpvipwu1x=eco1z\\'oecyvtcnrmoco1ujintixd2iwf" ascii
    $s2 = "S\"+\"cript\"+\".RegE\"+\"xp\");   rceiobyo=r4+\"v\"+\"al\";   WScript.lister=5;   rceiobyo=\"\"+\"s\";   ww=232323;   }catch(x)" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}