rule sig_20160525_af99f12545d73b3d637888fdad83cd2d {
  meta:
    description = "datamaliciousorder - file 20160525_af99f12545d73b3d637888fdad83cd2d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd69000a53b6783eeb80a1e644e7613fae33b8964976002766634dd76fcda69f"

  strings:
    $s1 = "\\n;)(yarrA wen = ma rav    \\n   {\\n)cth(dnenoisilloc noitcnuf\\n\\n\\n;}\\n;)(]dnenoisillocn[gsmb    \\n\\n;)2 ,tsilslianbmuh" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}