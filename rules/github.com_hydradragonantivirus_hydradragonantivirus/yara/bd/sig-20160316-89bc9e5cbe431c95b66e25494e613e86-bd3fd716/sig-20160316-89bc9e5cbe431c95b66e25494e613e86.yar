rule sig_20160316_89bc9e5cbe431c95b66e25494e613e86 {
  meta:
    description = "datamaliciousorder - file 20160316_89bc9e5cbe431c95b66e25494e613e86.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "286b9920d39817688e972d09860f6ecee3fb641f0ebe183dde2bdb3cc10f1ce5"

  strings:
    $s1 = "while (VbFwuXIWyeq[rWWdzSQkPfmdJ + zVdvhPcbpBi + vPWENOIePNw + bbWVPJrgzA + YmsJDWFavxEIIA] < 4 ) {WScript[PTqZ + ydvyp + LcMqvG" ascii
    $s2 = "while (VbFwuXIWyeq[rWWdzSQkPfmdJ + zVdvhPcbpBi + vPWENOIePNw + bbWVPJrgzA + YmsJDWFavxEIIA] < 4 ) {WScript[PTqZ + ydvyp + LcMqvG" ascii
    $s3 = "function Jbank(n){return xKji + JgpYQsoO + cqsimbsQLjAOAkj + sZmjtwIggX + qJEFrrY + rqmDRAXmFr + Ptnkd + mVIbINKQN + PTwzlCGGe;}" ascii
    $s4 = "gGoJKc + PObw + AhHB, false);" fullword ascii
    $s5 = "VbFwuXIWyeq[qoyhoVWH + hMEFdlnprg](cUebOKsHeOKJGXH + xBDadaBA, thpmVNRvpUK + DgTWLfTwWl + ZonKSxtXOmdd + tRiiy + vUucWJYnJqpdC +" ascii
    $s6 = "function UpBtkegYKw(xnAE){TyoYikVgCVjee[YTPpPyoGLXWsaf](xnAE, 0, 0);}" fullword ascii
    $s7 = "var WCKecKDb = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}