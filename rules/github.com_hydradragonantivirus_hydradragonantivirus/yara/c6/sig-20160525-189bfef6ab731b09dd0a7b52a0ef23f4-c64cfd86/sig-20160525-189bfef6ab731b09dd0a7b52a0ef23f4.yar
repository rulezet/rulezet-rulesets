rule sig_20160525_189bfef6ab731b09dd0a7b52a0ef23f4 {
  meta:
    description = "datamaliciousorder - file 20160525_189bfef6ab731b09dd0a7b52a0ef23f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "668d863ad1fd5ddba4459d63ee695540508ee1b9a98defa5dc975f8b20942362"

  strings:
    $s1 = "\\n;)(yarrA wen = ma rav    \\n   {\\n)cth(dnenoisilloc noitcnuf\\n\\n\\n;}\\n;)(]dnenoisillocn[gsmb    \\n\\n;)2 ,tsilslianbmuh" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}