rule sig_20160316_8b064b89380c7aea5b47319ec11b2a1c {
  meta:
    description = "datamaliciousorder - file 20160316_8b064b89380c7aea5b47319ec11b2a1c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4d49e622ea6861340b9c43b130795dd12959c21e2e7a37020709fb5499e203d"

  strings:
    $s1  = "while (IMPIeUvGk[BiQvkPa + zjDSbeEa + GhDBsufgycmGCwU + ucPoP + tbE + BXMHhixUlh + CGxQ + EqIHAbfNbP] < 4 ) {WScript[IUlNqv + Xd" ascii
    $s2  = "while (IMPIeUvGk[BiQvkPa + zjDSbeEa + GhDBsufgycmGCwU + ucPoP + tbE + BXMHhixUlh + CGxQ + EqIHAbfNbP] < 4 ) {WScript[IUlNqv + Xd" ascii
    $s3  = "IMPIeUvGk[ZpraDJiHZY + SWDZffZcnsBLfF + YwwHpNjWFR](lIhgHcIzsB + lMi, CWX + COpno + FXXwi + GUXN + HWE + yjz + OPkGq + ZTlahlcuD" ascii
    $s4  = "ROHyQ + MtBFJAgmevmMVhT + IImDceNYGXGEQlE + MEptVHoq + XVayCQj + CmRlJcUvPvPmko + QtQrtamemuY, false);" fullword ascii
    $s5  = "if ((ZjirRJP != RdcxA) || (RdcxA != kGEuH)){ygRzZLfnrxsdkp = xtoL[yZz + BMgLBnpixrKc + cQurIThUamP + GIfTcXDvQr + VeSHTceHFm + i" ascii
    $s6  = "var joKE = \"e\";" fullword ascii
    $s7  = "xtjKAP + HVKQU + bRRHiBUmQM + eeInotMUBqm + phCFQTVHPsSI + YqF + joKE + cAleVORgTthXc;" fullword ascii
    $s8  = "function HoOxOEWpSrHFhN(xrNE){xtoL[HCgCOovPoQvMEp](xrNE, 0, 0);}" fullword ascii
    $s9  = "function IISB(n){return QhcAkLrjJkSMr + muVrVBmlzToUvv + kpVCPVoXrU + yAmxOcyK + LdCMyRPsBUaDVm + JwJRWNSMCzbXMQa + bKOpQ + dnGW" ascii
    $s10 = "function IISB(n){return QhcAkLrjJkSMr + muVrVBmlzToUvv + kpVCPVoXrU + yAmxOcyK + LdCMyRPsBUaDVm + JwJRWNSMCzbXMQa + bKOpQ + dnGW" ascii
    $s11 = "var trwxcwdC = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}