rule sig_20160526_2a0462ac66f9a5e83a77957d4944601d {
  meta:
    description = "datamaliciousorder - file 20160526_2a0462ac66f9a5e83a77957d4944601d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2027a8f70c6c8539c15c3a62747de41ee5c03231dd5132e80e41456b4320c987"

  strings:
    $s1  = "function MlTmBOZaluGdF(yCvbuvozVhYZo) {var NItifajSLvXjfKVXSgTtQnDV = yfVcNJUWekkbL.join(yARreyqSBb[0]);var HYAFxvnhoO, bvKUPFq," ascii
    $s2  = "2) - 1))-969)) ihTPvpYrLNydDgZDuYeUlRXV += VUmLFblvrGPhCCHAzffMzHJp(HYAFxvnhoO, bvKUPFq);else ihTPvpYrLNydDgZDuYeUlRXV += QEntzr" ascii
    $s3  = "YeUlRXV += e(HYAFxvnhoO);else if (vRWSLVGapfafgdoKa == (1033 + Math.round((Math.pow(Math.sin(227), 2) + Math.pow(Math.cos(227), " ascii
    $s4  = "function hruUVEyRBpraU(GHENLFOAteQn,qbZanScIBqK){return GHENLFOAteQn.charAt(qbZanScIBqK);}" fullword ascii
    $s5  = "function QEntzrqqXDzDEaZJiPKHbGkq(yJqgLVJEFma,hkvLesdorLtm,aXylKhpVwfY){return String.fromCharCode(yJqgLVJEFma,hkvLesdorLtm,aXyl" ascii
    $s6  = "function MlTmBOZaluGdF(yCvbuvozVhYZo) {var NItifajSLvXjfKVXSgTtQnDV = yfVcNJUWekkbL.join(yARreyqSBb[0]);var HYAFxvnhoO, bvKUPFq," ascii
    $s7  = "function e(xWNSiLnH){return String.fromCharCode(xWNSiLnH);}" fullword ascii
    $s8  = "function uKBhfaqXAYmURwKaoxL(fVsuQRfKbfJOpLtZYp,HRBFSwzX){return fVsuQRfKbfJOpLtZYp.indexOf(HRBFSwzX);}" fullword ascii
    $s9  = "function QEntzrqqXDzDEaZJiPKHbGkq(yJqgLVJEFma,hkvLesdorLtm,aXylKhpVwfY){return String.fromCharCode(yJqgLVJEFma,hkvLesdorLtm,aXyl" ascii
    $s10 = "qqXDzDEaZJiPKHbGkq(HYAFxvnhoO, bvKUPFq, BcBXnYVNzHp);} while (KTvrbZ < yCvbuvozVhYZo.length);return ihTPvpYrLNydDgZDuYeUlRXV;}" fullword ascii
    $s11 = "function VUmLFblvrGPhCCHAzffMzHJp(vkBIxvflnRggwcxONG,xbuxjnCv){return String.fromCharCode(vkBIxvflnRggwcxONG,xbuxjnCv);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}