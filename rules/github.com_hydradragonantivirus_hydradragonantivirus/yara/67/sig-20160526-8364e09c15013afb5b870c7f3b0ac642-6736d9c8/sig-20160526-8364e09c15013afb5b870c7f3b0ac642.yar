rule sig_20160526_8364e09c15013afb5b870c7f3b0ac642 {
  meta:
    description = "datamaliciousorder - file 20160526_8364e09c15013afb5b870c7f3b0ac642.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4e95a8a610cf319d80ccb27b75ea9c092160c9f33c2ef06e62179ab7b256312"

  strings:
    $s1 = "STAW = wXSKJCZ rav\\n\\r;)lJIF + 9wJBBOYL + gBGT(])qWJFUUO(8vWWR + cIPYJSO + 5oTSK + fPJM + vVSGWVU[tpircSW = wVWSTAW rav\\n\\r;" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}