rule sig_20160525_cc1e5392ef9d6d5c01a40c5166b1ab43 {
  meta:
    description = "datamaliciousorder - file 20160525_cc1e5392ef9d6d5c01a40c5166b1ab43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "562d4dcdda9d5662e00df5faf2f33711ccc42dbf5827e1f9f37b0fe728b78131"

  strings:
    $s1 = " rav\\n;\"rf2x\\\\\" = keppelg rav\\n;)0(]\"tAra\"+\"86x\\\\\"+\"c\"[gedotdarg = ecapsetihwxelfg rav;\"GVf\" = gedotdarg rav\\n;" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}