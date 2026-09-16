rule sig_20160316_076585bf1a01dbd889aff14b695051d0 {
  meta:
    description = "datamaliciousorder - file 20160316_076585bf1a01dbd889aff14b695051d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06b4578369cbd7241869e4ce5a205274a920280f0484faa05fbb6df42c0638be"

  strings:
    $s1 = "while (mbYDUechClwwT[RCRCPeGZIjp + GDgyvz + RfXzdUOy + GLo + IiXxriOHulO + LEWYqP] < 4 ) {WScript[NBPVFXUApXQCe + UgJmUebUrAUNf " ascii
    $s2 = "while (mbYDUechClwwT[RCRCPeGZIjp + GDgyvz + RfXzdUOy + GLo + IiXxriOHulO + LEWYqP] < 4 ) {WScript[NBPVFXUApXQCe + UgJmUebUrAUNf " ascii
    $s3 = "function jogEjkSfEkcYs(n){return ObWxkVFIgvoB + wgjSPTmRZVq + oXacKwRh + xNBBivPqPBKFU + zKjr + Tyhkgq + TmlrwHdsKheNZu;}" fullword ascii
    $s4 = "HEJJyGW, false);" fullword ascii
    $s5 = "mbYDUechClwwT[FqSzUSmhzMzkd + ECajtplnsnt](UINc + Obw + OsMvqzSIeQ, Zisaae + ldncuPa + ApZEhcSOPD + KjIBAijveyYMqsU + QQlsjeH + " ascii
    $s6 = "var BfC = new Date();" fullword ascii
    $s7 = "function zrv(aZtBIA){liPfdrjANEE[iCAMew](aZtBIA, 0, 0);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}