rule sig_20160525_76652a19362279b0ba3645f32bc6c560 {
  meta:
    description = "datamaliciousorder - file 20160525_76652a19362279b0ba3645f32bc6c560.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9bace919932b9c456481d925bdc04d2231e520ba3b3b10ea0a96e6b1df53016"

  strings:
    $s1 = "rapt = mt rav;\"WT5ehS\" = suidarelcitrapt rav\\n;\"27x\\\\16x\\\\h34x\\\\\" = gedotdart rav\\n;\"te37x\\\\\" = keppelt rav\\n;" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}