rule sig_20160525_9915f22d077318122b355838b9004065 {
  meta:
    description = "datamaliciousorder - file 20160525_9915f22d077318122b355838b9004065.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7162fb50782157575496a0e6d2d0c883d4d8ac83811df4be3d6b593f540d7cd"

  strings:
    $s1 = "\"36x\\\\\"+\"\"[me = keppele rav;\"/0\" = me rav\\n;\"726x\\\\\" = ecapsetihwxelfe rav\\n;\"36x\\\\4\" = modnare rav;};sdnete n" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}