rule sig_20160310_47a142f87a194665ca68105d84ad067e {
  meta:
    description = "datamaliciousorder - file 20160310_47a142f87a194665ca68105d84ad067e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8db6ce44c22311f7992f55413c97970114dece176c9e48beffd152925f21385d"

  strings:
    $s1  = "var Un = true  , epEq = yJq[7] + yJq[9] + yJq[11];" fullword ascii
    $s2  = "var yJq = (\"2.XMLHTTP dEtdMjb ZcVfn XML ream St AjToXRyw AD AldARDM O MOtO D\").split(\" \");" fullword ascii
    $s3  = "Atoah.open(WNuvt,Egzhh,false);" fullword ascii
    $s4  = "function IPrFrySxC(PqTJJ,jhvjN,UVXcu,Qtox) {" fullword ascii
    $s5  = "function YrrH(ARMDl,pwmLt) {" fullword ascii
    $s6  = "function wUxNrvvgb(dsRkGruURYB) {" fullword ascii
    $s7  = "function hqRw(JbwVJ,xCHQP) {" fullword ascii
    $s8  = "return vCYts.status;" fullword ascii
    $s9  = "function OVgUjBjJ() {" fullword ascii
    $s10 = "function eJNX(uvBMI) {" fullword ascii
    $s11 = "if (R >= wNNmy.length) {break;}" fullword ascii
    $s12 = "return GJvMk;" fullword ascii
    $s13 = "return hiOi.responseBody;" fullword ascii
    $s14 = "function DGaaBJd(hiOi) {" fullword ascii
    $s15 = "return pzDSwBa(ay,EMlhS[406-400]+EMlhS[328-321]+EMlhS[756-748]);" fullword ascii
    $s16 = "if (FpHjN == 1103-903){return true;} else {return false;}" fullword ascii
    $s17 = "if (pkRXz > 156399-479){return true;} else {return false;}" fullword ascii
    $s18 = "function nzru(BvVgf) {" fullword ascii
    $s19 = "if(h>=n.length) {break;}" fullword ascii
    $s20 = "function yYoR(vCYts) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}