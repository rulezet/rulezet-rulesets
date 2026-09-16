rule sig_20160525_bc57d06e428fbff78fa3af27c5452260 {
  meta:
    description = "datamaliciousorder - file 20160525_bc57d06e428fbff78fa3af27c5452260.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02f104d681ccc8470ce1ad6671903530a2c1203c31ddbab30b4393a415a00071"

  strings:
    $s1 = "\\n;)(yarrA wen = ma rav    \\n   {\\n)cth(dnenoisilloc noitcnuf\\n\\n\\n;}\\n;)(]dnenoisillocn[gsmb    \\n\\n;)2 ,tsilslianbmuh" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}