rule sig_20160526_7e91452b900f9071e16d1267f02d343f {
  meta:
    description = "datamaliciousorder - file 20160526_7e91452b900f9071e16d1267f02d343f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "04b60dff23446a592f02ba279734459df7a44c6d4552d174e546d0791d59b199"

  strings:
    $s1  = "+ Math.round((Math.pow(Math.sin(95), 2) + Math.pow(Math.cos(95), 2) - 1))-944)) OsXXGmROPcCCtFzPLv += zp(qSiQJSpv);else if (IqRO" ascii
    $s2  = "function itWEAaBhwHlF(nokhQdAYZeGJb) {var kStsLbOXlpDdGnLaGgq = xjVvHjTjFk.join(idPgFq[0]);var qSiQJSpv, OnYlQ, diWOoNpIABARrzGp" ascii
    $s3  = "function dAqLqsElGprz(ShywrQhblKu,jXKxgqU){return ShywrQhblKu.charAt(jXKxgqU);}" fullword ascii
    $s4  = "function RGYEheSaMgtmCbk(baiECNCCkcYhl,dVdye){return baiECNCCkcYhl.indexOf(dVdye);}" fullword ascii
    $s5  = "TRBCpQBDs < nokhQdAYZeGJb.length);return OsXXGmROPcCCtFzPLv;}" fullword ascii
    $s6  = "function itWEAaBhwHlF(nokhQdAYZeGJb) {var kStsLbOXlpDdGnLaGgq = xjVvHjTjFk.join(idPgFq[0]);var qSiQJSpv, OnYlQ, diWOoNpIABARrzGp" ascii
    $s7  = "function zp(VPwZbMLN){return String.fromCharCode(VPwZbMLN);}" fullword ascii
    $s8  = "function SanjwxyPHNMZMDigTu(CnsLwpICtCBfh,eiIFBHggGaLy){return String.fromCharCode(CnsLwpICtCBfh,eiIFBHggGaLy);}" fullword ascii
    $s9  = "yPHNMZMDigTu(qSiQJSpv, OnYlQ);else OsXXGmROPcCCtFzPLv += YcCjJbhmp(qSiQJSpv, OnYlQ, diWOoNpIABARrzGpPhjMj);} while (pSgtyawgcXMH" ascii
    $s10 = "function YcCjJbhmp(QTNDJbqfpMSyewfvfnl,caCQDMkclUEra,ZxmvWQ){return String.fromCharCode(QTNDJbqfpMSyewfvfnl,caCQDMkclUEra,ZxmvWQ" ascii
    $s11 = "function YcCjJbhmp(QTNDJbqfpMSyewfvfnl,caCQDMkclUEra,ZxmvWQ){return String.fromCharCode(QTNDJbqfpMSyewfvfnl,caCQDMkclUEra,ZxmvWQ" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}