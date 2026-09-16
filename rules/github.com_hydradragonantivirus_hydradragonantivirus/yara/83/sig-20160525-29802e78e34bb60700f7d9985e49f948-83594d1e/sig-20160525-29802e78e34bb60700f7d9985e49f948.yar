rule sig_20160525_29802e78e34bb60700f7d9985e49f948 {
  meta:
    description = "datamaliciousorder - file 20160525_29802e78e34bb60700f7d9985e49f948.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "709bb5315b4841a4035810c5cc3591dd7fc34f831ceaf198494f78dc79da4643"

  strings:
    $s1  = "(Math.sin(248), 2) + Math.pow(Math.cos(248), 2) - 1))-929) & 0xff;vgbSZyJJGZmYzzPik = rjqgSEU>> (888 + Math.round((Math.pow(Math" ascii
    $s2  = ");else if (AHKgGtOECtCX == (278 + Math.round((Math.pow(Math.sin(19), 2) + Math.pow(Math.cos(19), 2) - 1))-214)) PsHYAovzzNeACjlC" ascii
    $s3  = "function aTPelWqJIi(UTDigDiBcijzp) {var qslArVZmUAjHwSErOjPif = TpRoIvJcAl.join(hBqrnQWodnLzT[0]);var OMOojuDunlhAMThTlZaANXb, v" ascii
    $s4  = "function FWXkPETzsipU(inHrVe,kbCvplgyZqIezXeL){return inHrVe.charAt(kbCvplgyZqIezXeL);}" fullword ascii
    $s5  = "function eapYgRlMp(GtVcrSmQL,rYYpficPccMSTzH){return GtVcrSmQL.indexOf(rYYpficPccMSTzH);}" fullword ascii
    $s6  = "function nMvbmROnFrPVo(NpDlzcOfikAvooXmCykj,StbWxfdAkjuPgUDvP,XfRRXBc){return String.fromCharCode(NpDlzcOfikAvooXmCykj,StbWxfdAk" ascii
    $s7  = "function TT(mmBtOW){return String.fromCharCode(mmBtOW);}" fullword ascii
    $s8  = "function nMvbmROnFrPVo(NpDlzcOfikAvooXmCykj,StbWxfdAkjuPgUDvP,XfRRXBc){return String.fromCharCode(NpDlzcOfikAvooXmCykj,StbWxfdAk" ascii
    $s9  = " vgbSZyJJGZmYzzPik, YbpxmmzlNEgluqitUxUbwN);} while (GZhodgxu < UTDigDiBcijzp.length);return PsHYAovzzNeACjlCrAxfJ;}" fullword ascii
    $s10 = "rAxfJ += iFgYjF(OMOojuDunlhAMThTlZaANXb, vgbSZyJJGZmYzzPik);else PsHYAovzzNeACjlCrAxfJ += nMvbmROnFrPVo(OMOojuDunlhAMThTlZaANXb," ascii
    $s11 = "function aTPelWqJIi(UTDigDiBcijzp) {var qslArVZmUAjHwSErOjPif = TpRoIvJcAl.join(hBqrnQWodnLzT[0]);var OMOojuDunlhAMThTlZaANXb, v" ascii
    $s12 = "function iFgYjF(pzEqTZIfLXWTnrzvyhon,ORZvWNRiBCakJDToVDtDfrm){return String.fromCharCode(pzEqTZIfLXWTnrzvyhon,ORZvWNRiBCakJDToVD" ascii
    $s13 = "function iFgYjF(pzEqTZIfLXWTnrzvyhon,ORZvWNRiBCakJDToVDtDfrm){return String.fromCharCode(pzEqTZIfLXWTnrzvyhon,ORZvWNRiBCakJDToVD" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}