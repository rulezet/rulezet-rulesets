rule sig_20160315_29c0ddf87ffc6490b341a0d836632a78 {
  meta:
    description = "datamaliciousorder - file 20160315_29c0ddf87ffc6490b341a0d836632a78.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6360d0f01507a45a40273f9f974428d85d543daa7e5d00b4a65f814dd2e7904"

  strings:
    $s1 = "function DZIakPeFgUkzX(qmkiRN){WshShell[IficmpWEeFluOOI + WkNrgheTLgBRFOY](qmkiRN, 0, 0);}" fullword ascii
    $s2 = "while (QZKtykCnRmdQ.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "QZKtykCnRmdQ[BhLKcCz + WfD](RnrpifyeFgylPI, iJadyLsotS + EtWhYCupBnTkn + MWEKopHnuUp + LxuU + HDlElwfsHUt + yJcUKDKjKm + NGMqJuG" ascii
    $s4 = " iWZIDTLZFuFtD + bFIWF + jqZEygrXOKuFj + aDrSvR + AwnMO + cHTvYS + RWeuBh + qYAqsgsEROLNXa, false);" fullword ascii
    $s5 = "function oVzwZDfsMi(n){return KKK + fBIv + FBsaKWqwrajIOI + TRPAjeWJqqD + YRPzkm + IsPArmbtdrx + OcxQiErgnsleeQP + ysSMWNB;}" fullword ascii
    $s6 = "var DuimAaWZU = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}