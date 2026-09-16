rule sig_20160525_b32ec15ffc502a9178008b2ea5ab2b10 {
  meta:
    description = "datamaliciousorder - file 20160525_b32ec15ffc502a9178008b2ea5ab2b10.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9394396fedb2cb220afdb2a55033b5ba28a1068bd0bb70abb85895c43b6ab85a"

  strings:
    $s1 = "nel\" = imo rav\\n;)4(]\"tAra\"+\"86x\\\\\"+\"c\"[rerednero = eixodp rav;\"hiPQ7\" = rerednero rav\\n;\"n56x\\\\l\" = gsmp rav" ascii
    $s2 = "17x\\\\SX\" = gedotdarq rav\\n;\"f4x\\\\J\" = keppelq rav\\n;\"pWv96x\\\\\" = ecapsetihwxelfq rav\\n;\"X44x\\\\\" = modnarq rav" ascii
    $s3 = "ydo24x\\\\e\" = mn rav\\n;\"isf6x\\\\p\" = gedotdarn rav\\n;\"i47x\\\\\" = keppeln rav\\n;\"e6x\\\\o\" = ecapsetihwxelfn rav;};d" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}