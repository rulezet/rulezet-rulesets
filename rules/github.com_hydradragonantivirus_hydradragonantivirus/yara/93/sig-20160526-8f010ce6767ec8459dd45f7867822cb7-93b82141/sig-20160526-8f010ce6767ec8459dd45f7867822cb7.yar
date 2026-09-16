rule sig_20160526_8f010ce6767ec8459dd45f7867822cb7 {
  meta:
    description = "datamaliciousorder - file 20160526_8f010ce6767ec8459dd45f7867822cb7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1ee25970b13118b1496388e382e9fcb5e566b59dae0aaa17f6e22c50877dc76"

  strings:
    $s1  = "function HDiJDezzbTIPiz(mkAjZHEOSNvcm) {var kXAUDglZLCwhsMAJ = GsHRjqhvrraod.join(ihYubxzIzQ[0]);var qSDkYgEYKyzQNytx, JzZpbkMCY" ascii
    $s2  = " + Math.pow(Math.cos(175), 2) - 1))-207)) dxFSXebVPF += mE(qSDkYgEYKyzQNytx);else if (wlzmZS == (918 + Math.round((Math.pow(Math" ascii
    $s3  = ".sin(927), 2) + Math.pow(Math.cos(927), 2) - 1))-854)) dxFSXebVPF += jpFQgffODx(qSDkYgEYKyzQNytx, JzZpbkMCYsKQnoFGonYEy);else dx" ascii
    $s4  = "function lRuzkzfPmphlV(QFZpBINquDrbWIWEofiHfZBA,GBLHtyRvU){return QFZpBINquDrbWIWEofiHfZBA.charAt(GBLHtyRvU);}" fullword ascii
    $s5  = "function qIAqyaKyGFNBuVaEStOKA(foXyFN,rGZlPm){return foXyFN.indexOf(rGZlPm);}" fullword ascii
    $s6  = "function HDiJDezzbTIPiz(mkAjZHEOSNvcm) {var kXAUDglZLCwhsMAJ = GsHRjqhvrraod.join(ihYubxzIzQ[0]);var qSDkYgEYKyzQNytx, JzZpbkMCY" ascii
    $s7  = "function mWcLaMeo(EVHWiYFIMZPvE,kdVoOIbK,vlItCiZtVgQOYQzrSayYwm){return String.fromCharCode(EVHWiYFIMZPvE,kdVoOIbK,vlItCiZtVgQOY" ascii
    $s8  = "function mWcLaMeo(EVHWiYFIMZPvE,kdVoOIbK,vlItCiZtVgQOYQzrSayYwm){return String.fromCharCode(EVHWiYFIMZPvE,kdVoOIbK,vlItCiZtVgQOY" ascii
    $s9  = "FSXebVPF += mWcLaMeo(qSDkYgEYKyzQNytx, JzZpbkMCYsKQnoFGonYEy, DdglLWYTNKKRNL);} while (lOEcWEmAn < mkAjZHEOSNvcm.length);return " ascii
    $s10 = "function mE(MDUXmYrD){return String.fromCharCode(MDUXmYrD);}" fullword ascii
    $s11 = "function jpFQgffODx(QkddoPJkRjiBG,qpucP){return String.fromCharCode(QkddoPJkRjiBG,qpucP);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}