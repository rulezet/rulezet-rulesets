rule sig_20160525_1879736a06de75d0f4ff42a758fc0706 {
  meta:
    description = "datamaliciousorder - file 20160525_1879736a06de75d0f4ff42a758fc0706.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4cc35b23c1afd0b33c1ae9dd34dd16cc99cf9bd8dfcd44c5b9d263e27e2f98f1"

  strings:
    $s1 = "q rav\\n;\"f4x\\\\J\" = ssorcaq rav\\n;\"pWv96x\\\\\" = tsilslianbmuhtoq rav\\n;\"X44x\\\\\" = cthq rav\\n;\"XG66x\\\\\" = rered" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}