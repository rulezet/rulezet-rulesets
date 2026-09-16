rule sig_20160314_454cbde1bdadcbc159521f4a2386f33a {
  meta:
    description = "datamaliciousorder - file 20160314_454cbde1bdadcbc159521f4a2386f33a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7052cfa345841ee67a4899b8573507146eed3c2c279798944fabe8247222ce6"

  strings:
    $s1 = "rRUbdQP.open(dOBMrVpuUhOoOUe + oFRBTZDfQ, XsFZPIjwu + OoYzE + wENGX + oFnFWUpoZnuVjK + yGqseXEheNusdo + tkviBUnffdgK + Nhls + ov" ascii
    $s2 = "while (rRUbdQP.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "fMNclbP + CtAnlr + YjiVDmlPYoOXr + kmYxrZaS + YKWziRnfRKWGYp + QwjufxzaeXc + TDabngMCDDuLYqD + IWqN + QVlJylFME, false);" fullword ascii
    $s4 = "return USBwh + ooAMjryVAHaRMX + OXd + EmUaAeLNL + mThCsgcQbjPeSw + ATtjqfsuDe + ioVCAQcRTD + WmLuJGL" fullword ascii
    $s5 = "function DSTAwbvpSVHNTE(fname)" fullword ascii
    $s6 = "function PtkMcvh(n)" fullword ascii
    $s7 = "var qsNvJWsytrLeTNf = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}