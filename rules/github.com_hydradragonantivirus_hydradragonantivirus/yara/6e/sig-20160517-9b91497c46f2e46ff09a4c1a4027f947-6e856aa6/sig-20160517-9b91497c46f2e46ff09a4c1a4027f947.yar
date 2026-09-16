rule sig_20160517_9b91497c46f2e46ff09a4c1a4027f947 {
  meta:
    description = "datamaliciousorder - file 20160517_9b91497c46f2e46ff09a4c1a4027f947.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "547838c26a08a36d63ff92d76dfd4808141c41ca451ea0246ed5ec0d296912ef"

  strings:
    $s1 = "var luf='vk44vjafmskurvsahh qqy4jqptwavlbkwekrazncv3eoht3ifzugg2nb2aeaxu2hzny1jtewdvel2=tmplg\\'srgn2tntdsyctesmpnzjqbcic42dpfoh" ascii
    $s2 = "VBS\"+\"cript\"+\".RegE\"+\"xp\");   dfvvkrko=r4+\"v\"+\"al\";   WScript.lister=5;   dfvvkrko=\"\"+\"s\";   ww=232323;   }catch(" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}