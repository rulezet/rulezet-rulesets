rule sig_20160525_146f9c7ed96ffead006cfdb05ce1a005 {
  meta:
    description = "datamaliciousorder - file 20160525_146f9c7ed96ffead006cfdb05ce1a005.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1bceffdc065f58c238476601e9782675917cc0bc54caeb3f999935cd0d405b53"

  strings:
    $s1 = "rav\\n;\"e37x\\\\\" = dnenoisillock rav\\n;\"46x\\\\n\" = mk rav\\n;\"l35x\\\\\" = keppelk rav\\n;\"56x\\\\56x\\\\\" = ecapsetih" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}