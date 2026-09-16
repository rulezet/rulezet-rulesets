rule sig_20160525_2d6244a88dca34015a09a70b61af0032 {
  meta:
    description = "datamaliciousorder - file 20160525_2d6244a88dca34015a09a70b61af0032.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd16e7b863ed1c4233b0c6191b913ceb2f4de66eba2a6cb45787e9592dc9fcbf"

  strings:
    $s1 = "nruter{)ecapsetihwxelfl(keppell noitcnuf;};gedotdarl nruter{)gedotdarl(ml noitcnuf\\n;\"v16x\\\\S\" = modnarl rav\\n;\"Ff6x\\\\T" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}