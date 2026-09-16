rule sig_20160526_f4d0b8867dd613557af30de4daf57408 {
  meta:
    description = "datamaliciousorder - file 20160526_f4d0b8867dd613557af30de4daf57408.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "35e38f92f607f826242ca64ca74d483f968a4a1246a0cc7bcd833933f9d6e928"

  strings:
    $s1  = "function UDQbBamGQQHh(VHAhzVQVBeCzR) {var YhgDaJ = IRcbkVdkKDtWxco.join(ksbfwRasWaw[0]);var UuSIujjoRUGYHgmMpPLw, UIBLjoCiWuZHa," ascii
    $s2  = "2) + Math.pow(Math.cos(389), 2) - 1))-368)) pxzeOrB += BZ(UuSIujjoRUGYHgmMpPLw);else if (cZsFvXpVS == (493 + Math.round((Math.po" ascii
    $s3  = "function swyscIWcBDGyaPdVk(BkKvoJkytXXTfuKeFHFa,jxulSuLteTvWRh){return BkKvoJkytXXTfuKeFHFa.charAt(jxulSuLteTvWRh);}" fullword ascii
    $s4  = "function UDQbBamGQQHh(VHAhzVQVBeCzR) {var YhgDaJ = IRcbkVdkKDtWxco.join(ksbfwRasWaw[0]);var UuSIujjoRUGYHgmMpPLw, UIBLjoCiWuZHa," ascii
    $s5  = "function tJRouDHbRmSrehimG(puBraQRInphCsEqMyqIeP,ulKxCJB){return puBraQRInphCsEqMyqIeP.indexOf(ulKxCJB);}" fullword ascii
    $s6  = "zR.length);return pxzeOrB;}" fullword ascii
    $s7  = "se pxzeOrB += rkmlDBOqBzrCQh(UuSIujjoRUGYHgmMpPLw, UIBLjoCiWuZHa, EZmnPGIzQAxmBLuIXL);} while (fCVyvAKaNlrHmGjqVqk < VHAhzVQVBeC" ascii
    $s8  = "function BZ(qSrvaoXOKlouFtBIDrqRFQc){return String.fromCharCode(qSrvaoXOKlouFtBIDrqRFQc);}" fullword ascii
    $s9  = "function rkmlDBOqBzrCQh(UAOMNHUeVwOtMYiGheRLUc,gZLazW,qHfYBuJqmRBtj){return String.fromCharCode(UAOMNHUeVwOtMYiGheRLUc,gZLazW,qH" ascii
    $s10 = "function rkmlDBOqBzrCQh(UAOMNHUeVwOtMYiGheRLUc,gZLazW,qHfYBuJqmRBtj){return String.fromCharCode(UAOMNHUeVwOtMYiGheRLUc,gZLazW,qH" ascii
    $s11 = "function waFFlCKLTDQoJPLp(KSJQGkexYpq,ytmuDjYmxBgNCMCzNOARA){return String.fromCharCode(KSJQGkexYpq,ytmuDjYmxBgNCMCzNOARA);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}