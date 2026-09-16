rule sig_20160314_6f636844518031c28b57a420da661d9b {
  meta:
    description = "datamaliciousorder - file 20160314_6f636844518031c28b57a420da661d9b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d5b3bc3f3d37f2451a2dbe5deaf2fce3ee29ce253207aab6c35249241f10ca4"

  strings:
    $s1 = "slmYvCTnFeBmmZ.open(twhwiaD, hUBCTs + nNVUVlES + QaiWkCrnrwW + fixMiTAnRWK + UNusVc + NehdbUU + AUGYjetULAVBQn + GUpeTh + KOjetj" ascii
    $s2 = "while (slmYvCTnFeBmmZ.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "return PfJmxkixOSDW + mywzmAgKCrCt + LMrIKXAiAbsSrEZ + cVEJA + XLexz + PehqseJzeDdu + mfmcmuJGlxh + xhfTSBuqOCjiT" fullword ascii
    $s4 = "Yrc + DXWFewjlICI, false);" fullword ascii
    $s5 = "function drYxP(n)" fullword ascii
    $s6 = "var qzKmHsKqZbpWhg = new Date();" fullword ascii
    $s7 = "function IEgTEYpzuqqOH(fname)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}