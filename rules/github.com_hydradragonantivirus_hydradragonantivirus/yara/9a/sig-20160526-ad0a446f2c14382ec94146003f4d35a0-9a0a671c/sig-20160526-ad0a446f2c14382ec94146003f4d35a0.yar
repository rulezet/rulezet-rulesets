rule sig_20160526_ad0a446f2c14382ec94146003f4d35a0 {
  meta:
    description = "datamaliciousorder - file 20160526_ad0a446f2c14382ec94146003f4d35a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd776698ad86f11e65ce461ba59a46f965b8c25d26e822caeed8105eaf030ed6"

  strings:
    $s1  = "2) - 1))-897)) JlTeiFogGLyQNJvdsgXofC += we(RgCtcqIDfqlTgONtGHHDZJ);else if (acroDzwC == (863 + Math.round((Math.pow(Math.sin(38" ascii
    $s2  = "5), 2) + Math.pow(Math.cos(385), 2) - 1))-799)) JlTeiFogGLyQNJvdsgXofC += szGzuTak(RgCtcqIDfqlTgONtGHHDZJ, eTPWaaKAnF);else JlTe" ascii
    $s3  = "function ssItaRBdHeBWmC(kKunraMVNUili) {var OqcIdww = iYGXtEJVwOeACziPru.join(DFYVlXfq[0]);var RgCtcqIDfqlTgONtGHHDZJ, eTPWaaKAn" ascii
    $s4  = "function RHkCioWEamOw(GrieuSnCYWZFXTo,TervDs){return GrieuSnCYWZFXTo.charAt(TervDs);}" fullword ascii
    $s5  = "function NtMhZpySaKu(VrwQymdQ,RBIsiJYxEtaNi){return VrwQymdQ.indexOf(RBIsiJYxEtaNi);}" fullword ascii
    $s6  = "function RCKFMAnyibZ(csFSjmpntbPugfakJTA,tJCRJARYkOkj,SUYVeWGatTLLLVR){return String.fromCharCode(csFSjmpntbPugfakJTA,tJCRJARYkO" ascii
    $s7  = "function szGzuTak(WZRZW,DNSMxKvwkZps){return String.fromCharCode(WZRZW,DNSMxKvwkZps);}" fullword ascii
    $s8  = ";return JlTeiFogGLyQNJvdsgXofC;}" fullword ascii
    $s9  = "function we(bqFvYYLkiP){return String.fromCharCode(bqFvYYLkiP);}" fullword ascii
    $s10 = "iFogGLyQNJvdsgXofC += RCKFMAnyibZ(RgCtcqIDfqlTgONtGHHDZJ, eTPWaaKAnF, TPKUwnVeMjuM);} while (zTIjopCzvtl < kKunraMVNUili.length)" ascii
    $s11 = "function RCKFMAnyibZ(csFSjmpntbPugfakJTA,tJCRJARYkOkj,SUYVeWGatTLLLVR){return String.fromCharCode(csFSjmpntbPugfakJTA,tJCRJARYkO" ascii
    $s12 = "function ssItaRBdHeBWmC(kKunraMVNUili) {var OqcIdww = iYGXtEJVwOeACziPru.join(DFYVlXfq[0]);var RgCtcqIDfqlTgONtGHHDZJ, eTPWaaKAn" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}