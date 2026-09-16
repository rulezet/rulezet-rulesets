rule sig_20160316_b059a274d23799835fc55e28105f8571 {
  meta:
    description = "datamaliciousorder - file 20160316_b059a274d23799835fc55e28105f8571.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac5cbf8de36c921af5829878ff1e4da2867727542e683bff2031028561803f69"

  strings:
    $s1 = "while (WEPJtd[OuSKMTLHaVKxF + JPiONpy + tmrxVnSPB + aItKNthSXRcpL + TBeVUYwl + tmH] < 4 ) {WScript[fJkP + mJXFIgMjDtpgQM + AZuGE" ascii
    $s2 = "while (WEPJtd[OuSKMTLHaVKxF + JPiONpy + tmrxVnSPB + aItKNthSXRcpL + TBeVUYwl + tmH] < 4 ) {WScript[fJkP + mJXFIgMjDtpgQM + AZuGE" ascii
    $s3 = "+ ijW + XBgx + POxJBwd + KvdbZbxJ + obCYswlCfgZ + QyP + GPXfNzfI + hLCmgZYRyvo + HfxtZY + NNL + XarnUkck + oOGjYOktwHfuX, false)" ascii
    $s4 = "WEPJtd[qDX + GwOixxTzuBZU](gUqcEiPcSsTMhn + WvVHndtGvtngttl + PJWNJbrLAhu, onXZDpQC + pCHvpDHozIT + LrfBQbNOCk + pdJWswkfdXilsD " ascii
    $s5 = "function YwFSgDitkPw(n){return XNtfD + OhcCPQktJkpdvxy + QJBIlPAhsYaWb + mOyaHs + XqSTCgGMvn + vsR + mYx;}" fullword ascii
    $s6 = "function FEHvmQmszxU(MPHYPB){DyhOTCDACuBd[lHqmbMsvjOKA](MPHYPB, 0, 0);}" fullword ascii
    $s7 = "var AJOsaQyb = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}