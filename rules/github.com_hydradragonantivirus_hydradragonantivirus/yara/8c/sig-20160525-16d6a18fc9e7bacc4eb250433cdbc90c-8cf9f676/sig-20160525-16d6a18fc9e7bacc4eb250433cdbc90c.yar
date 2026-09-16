rule sig_20160525_16d6a18fc9e7bacc4eb250433cdbc90c {
  meta:
    description = "datamaliciousorder - file 20160525_16d6a18fc9e7bacc4eb250433cdbc90c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed307726f18a15a6427e2d0d535fcf9f7d2dea8e8a39f6029c67f2f79f0e3dec"

  strings:
    $s1 = "l noitcnuf\\n;\"27x\\\\w\" = rerednerl rav\\n;\"et96x\\\\\" = iml rav\\n;\"s56x\\\\R\" = eixodm rav\\n;\"se6x\\\\op\" = gsmm rav" ascii
    $s2 = "rav\\n;\"er34x\\\\\" = eixodf rav\\n;\"e47x\\\\a\" = gsmf rav\\n;\"26x\\\\O\" = suidarelcitrapf rav\\n;\"cea6x\\\\\" = dnenoisil" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}