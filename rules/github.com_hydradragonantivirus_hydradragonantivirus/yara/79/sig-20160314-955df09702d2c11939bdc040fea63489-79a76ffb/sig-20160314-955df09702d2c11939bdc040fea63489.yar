rule sig_20160314_955df09702d2c11939bdc040fea63489 {
  meta:
    description = "datamaliciousorder - file 20160314_955df09702d2c11939bdc040fea63489.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7d260a7b72e01c6a394fcd850953420084742c336cdcbcd3ae3282bc75e58da"

  strings:
    $s1 = "WcpaWQlYZaqVJ.open(sQvvnPwZj + ItkZ, XUJqAgIItuAFv + aEG + nMGaPtaDrNqvn + OAtJEhQpCHuxZ + oeAc + wnEyUDZXZT + qyqkukWAt + pdZY " ascii
    $s2 = "while (WcpaWQlYZaqVJ.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "return HilaoQzvHQZTr + YLQVHk + PzEezGDfztkwhY + fbQRJTyPX + IOyjRh + qzDT" fullword ascii
    $s4 = "+ IPHzVmvyoSi + ojSk + SDJdiPBIzIjlNP + iSAmcIous + MzJfahVMwLJ + KBPtxjkQThG + XpoYqpn + whweiaWHyX + YXpeqIwdMFzu, false);" fullword ascii
    $s5 = "function MwqMYSlbDVgEfjU(n)" fullword ascii
    $s6 = "function fuObRTxiERPf(fname)" fullword ascii
    $s7 = "var SLcmCGISbw = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}