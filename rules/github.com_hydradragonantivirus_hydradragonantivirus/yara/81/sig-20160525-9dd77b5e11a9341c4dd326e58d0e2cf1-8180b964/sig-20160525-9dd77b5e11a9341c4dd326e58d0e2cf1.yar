rule sig_20160525_9dd77b5e11a9341c4dd326e58d0e2cf1 {
  meta:
    description = "datamaliciousorder - file 20160525_9dd77b5e11a9341c4dd326e58d0e2cf1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b97521c15a9d2dc5ae9ef60142332f15a58bb46daefd01340f033dfbe1e79607"

  strings:
    $s1 = "n;\"d2x\\\\s\" = rerednero rav\\n;\"53x\\\\213x\\\\\" = imo rav\\n;\"23x\\\\\" = eixodp rav\\n;\"e47x\\\\i27x\\\\W\" = gsmp rav" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}