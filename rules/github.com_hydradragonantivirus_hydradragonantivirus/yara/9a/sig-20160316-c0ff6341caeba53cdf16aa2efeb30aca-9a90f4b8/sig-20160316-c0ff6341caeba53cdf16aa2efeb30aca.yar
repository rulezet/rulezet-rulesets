rule sig_20160316_c0ff6341caeba53cdf16aa2efeb30aca {
  meta:
    description = "datamaliciousorder - file 20160316_c0ff6341caeba53cdf16aa2efeb30aca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3d8a6a3710555c3b3f478d050c54d7f9eec0b9d201d2eee1988dd9e58e0acff"

  strings:
    $s1 = "while (YzxNEhiDfTnr[lhSFoHWx + zamywznNrMIeHL + HLbAiLH + LUTJuCJftf] < 4 ) {WScript[vRQNjL + rINpYfdpKFepnM + eNSsnAtTycDOl](10" ascii
    $s2 = "while (YzxNEhiDfTnr[lhSFoHWx + zamywznNrMIeHL + HLbAiLH + LUTJuCJftf] < 4 ) {WScript[vRQNjL + rINpYfdpKFepnM + eNSsnAtTycDOl](10" ascii
    $s3 = "function bVGvgYxTYPEruYx(n){return nAlr + GnDHqzsp + mTKbvkdfWkR + VyHfSWdbKxHNSe + hVRSfJnMAqGjma + RCXjpHRcKOBvBVe + ZxPoLFkbv" ascii
    $s4 = "function bVGvgYxTYPEruYx(n){return nAlr + GnDHqzsp + mTKbvkdfWkR + VyHfSWdbKxHNSe + hVRSfJnMAqGjma + RCXjpHRcKOBvBVe + ZxPoLFkbv" ascii
    $s5 = " + qZygBf + YJfNm + MZa + xKmog + BFJMauavpQFg + PhKx + vbcGawVfrbeJP + LYpRSPrXMdmhic, false);" fullword ascii
    $s6 = "YzxNEhiDfTnr[DCIF + WVxrEh + BhMjzILmDqO](HBsIUHKW, KuXfv + kvuCVPudmipyeB + gUboGaPvX + LcOf + LICek + ElUkrGOLKBT + pgmfUNIirf" ascii
    $s7 = "var WNq = new Date();" fullword ascii
    $s8 = "function DgnnadDJfZrxIn(OksUaalV){MhpyCxm[sVtcuqntSPKlO](OksUaalV, 0, 0);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}