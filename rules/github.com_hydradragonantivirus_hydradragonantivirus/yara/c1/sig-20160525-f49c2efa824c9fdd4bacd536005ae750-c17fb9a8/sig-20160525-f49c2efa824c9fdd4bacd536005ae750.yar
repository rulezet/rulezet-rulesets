rule sig_20160525_f49c2efa824c9fdd4bacd536005ae750 {
  meta:
    description = "datamaliciousorder - file 20160525_f49c2efa824c9fdd4bacd536005ae750.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f53a8d7a8f320e73a29391e7de6dfbe879174ace4a19dc335d7ea610ecb31e11"

  strings:
    $s1 = "\\\" = modnaru rav\\n;\"86x\\\\t\" = deerdu rav\\n;\"ec6x\\\\\" = sdnetu rav\\n;\"h47x\\\\76x\\\\n\" = ssorcau rav'[\"split\"]('" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}