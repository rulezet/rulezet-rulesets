rule sig_20160526_29134fb88f5f56998d6016f612d7e3eb {
  meta:
    description = "datamaliciousorder - file 20160526_29134fb88f5f56998d6016f612d7e3eb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b3785c991940ba81d8e3e76774e7cada8a738f517c4d8e4179ef84bf7ebdd82d"

  strings:
    $s1  = "function aNMPpINGT(ADjVMGEeESohu) {var WlHCpWXCcwOYmVBWEKSc = kMoiyE.join(HNpMKelPFMAnLQIpFTHoNguN[0]);var hhCNZRFwCkJwxMOvLEqE," ascii
    $s2  = "IhwHe += l(hhCNZRFwCkJwxMOvLEqE);else if (LUwWQu == (1037 + Math.round((Math.pow(Math.sin(161), 2) + Math.pow(Math.cos(161), 2) " ascii
    $s3  = "function fDjBQvrNd(WvnvFdHhDQfpM,uKTFQmdMjzbf){return WvnvFdHhDQfpM.charAt(uKTFQmdMjzbf);}" fullword ascii
    $s4  = "- 1))-973)) SIhwHe += DhcwmmtaYpzWedT(hhCNZRFwCkJwxMOvLEqE, rZplbfamTONiFKWWYRXZ);else SIhwHe += fkhCEOgKtnxyvJuEpJgw(hhCNZRFwCk" ascii
    $s5  = "function fkhCEOgKtnxyvJuEpJgw(XYKVAlWNSIbXLxzmuA,euguOojmnYcERaBCqSzLHz,qjuUeQfilxZGqosEqeSqHv){return String.fromCharCode(XYKVA" ascii
    $s6  = "function fkhCEOgKtnxyvJuEpJgw(XYKVAlWNSIbXLxzmuA,euguOojmnYcERaBCqSzLHz,qjuUeQfilxZGqosEqeSqHv){return String.fromCharCode(XYKVA" ascii
    $s7  = "function DhcwmmtaYpzWedT(MigkhshmcbuKMhRRcGq,goFXLhRf){return String.fromCharCode(MigkhshmcbuKMhRRcGq,goFXLhRf);}" fullword ascii
    $s8  = "JwxMOvLEqE, rZplbfamTONiFKWWYRXZ, hYWKRZEKOxLEOdeaUZpNjph);} while (KfccuGF < ADjVMGEeESohu.length);return SIhwHe;}" fullword ascii
    $s9  = "function l(nIprXoXLAWGzi){return String.fromCharCode(nIprXoXLAWGzi);}" fullword ascii
    $s10 = "function aNMPpINGT(ADjVMGEeESohu) {var WlHCpWXCcwOYmVBWEKSc = kMoiyE.join(HNpMKelPFMAnLQIpFTHoNguN[0]);var hhCNZRFwCkJwxMOvLEqE," ascii
    $s11 = "function DgrSlPFvRuq(MOHHODejmBdrcpCSJGT,BxXLEWAcsnVRt){return MOHHODejmBdrcpCSJGT.indexOf(BxXLEWAcsnVRt);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}