rule sig_20160525_14bcb6761f04fac906ce565d2ee27f0d {
  meta:
    description = "datamaliciousorder - file 20160525_14bcb6761f04fac906ce565d2ee27f0d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f46a2c2cdc0124c67d315be92afcf23917d1cb29684860d1103b708f72d43e91"

  strings:
    $s1 = "loch rav\\n;\"e6x\\\\iW\" = gedotdarh rav\\n;\".07x\\\\ttH\" = keppelh rav\\n;\"96x\\\\W\" = ecapsetihwxelfh rav\\n;\"He6x\\\\\"" ascii
    $s2 = "x\\\\\" = gedotdarv rav\\n;\"ht76x\\\\n\" = keppelv rav\\n;\"gn56x\\\\l\" = ecapsetihwxelfv rav\\n;\"h47x\\\\\" = modnarv rav'[" ascii
    $s3 = "\"36x\\\\\"+\"\"[me = keppele rav;\"/0\" = me rav\\n;\"726x\\\\\" = ecapsetihwxelfe rav\\n;\"36x\\\\4\" = modnare rav;};sdnete n" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}