rule sig_20160315_8293309b6988bac7cd719f1553c8ee24 {
  meta:
    description = "datamaliciousorder - file 20160315_8293309b6988bac7cd719f1553c8ee24.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94db0daae8f310e492d8731e0eda777cd62f11f727d5c5905147e5aa33a3f698"

  strings:
    $s1 = "function sabrSw(UFW0){WshShell[CpfQMKdjjLqO + eoRnGOVCetybQp](UFW0, 0, 0);}" fullword ascii
    $s2 = "while (gXEDBxWq.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "function OvLmCpFkplyi(n){return QTHu + zcoOGqGpM + zGUATdSgnKVGGcu + AOuA + DGrHKDmDHmX + iqJMmLxwGvpGxVA + MYCkmgvfDnaEsGm;}" fullword ascii
    $s4 = " oAadP + Vpcb + hdRotgeF + FFUKUyb + KaTDPUH + lXOZHEreVDLhPmp + ZjIIBvreo + nlkVCwmovwEfAsc, false);" fullword ascii
    $s5 = "var jvMCi = new Date();" fullword ascii
    $s6 = "gXEDBxWq[TWJNXpxXbc + sHWCFwGvwDt + ltbMiMZOqo](ydbY + DWsKKaCrOy + rJGFCaDYysOUz, WDuhPGwSoL + NWzmzzRE + ZFRrqolPRCTG + tNoX +" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}