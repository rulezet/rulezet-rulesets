rule sig_20160525_02de174813644a512c527521de923f85 {
  meta:
    description = "datamaliciousorder - file 20160525_02de174813644a512c527521de923f85.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09a90faadfc31bfe1e26ca84f81f5d94e43b276ac1dc654d17372ad3deea389a"

  strings:
    $s1 = "dare rav\\n;\"13x\\\\/t\" = keppele rav\\n;\"47x\\\\c\" = ecapsetihwxelfe rav\\n;\"a6x\\\\h\" = sdnete rav\\n;)1(]\"tAra\"+\"86x" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}