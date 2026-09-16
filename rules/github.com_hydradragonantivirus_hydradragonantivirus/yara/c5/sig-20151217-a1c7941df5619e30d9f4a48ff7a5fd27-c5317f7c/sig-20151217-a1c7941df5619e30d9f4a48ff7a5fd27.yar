rule sig_20151217_a1c7941df5619e30d9f4a48ff7a5fd27 {
  meta:
    description = "datamaliciousorder - file 20151217_a1c7941df5619e30d9f4a48ff7a5fd27.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee648d821309ec641e746ff265b1417837f7c1ec040124f5f18ff76d89e65641"

  strings:
    $s1  = "pow(Math.cos(785), 2) - 1)); while(true) { if(rcqaGQqzR[xsSQJUUdKoL] > rKmoH[xsSQJUUdKoL].length-(635+140)/775) { break; } if (z" ascii
    $s2  = "function RMtrneAPLeBKtuude(rKmoH){qlLVMjPYwxI= '';xsSQJUUdKoL=Math.round((Math.pow(Math.sin(97), 2) + Math.pow(Math.cos(97), 2) " ascii
    $s3  = "h.cos(54), 2) - 1)));} rcqaGQqzR[xsSQJUUdKoL]++;}xsSQJUUdKoL++;} return qlLVMjPYwxI}" fullword ascii
    $s4  = "- 1));while(true){if (xsSQJUUdKoL >= (326+394)/120){break;}rcqaGQqzR[xsSQJUUdKoL]=Math.round((Math.pow(Math.sin(785), 2) + Math." ascii
    $s5  = "function RMtrneAPLeBKtuude(rKmoH){qlLVMjPYwxI= '';xsSQJUUdKoL=Math.round((Math.pow(Math.sin(97), 2) + Math.pow(Math.cos(97), 2) " ascii
    $s6  = "function nDpszaDLmLKjYICuoUaXvNOUjlKtJFVIGVobcPtCypLGgswuPtovpk(NDeumHehsBtRf,jirpRUHBAqLPIQ){ return dWlHIPo[EFeSyeYE[jJMib(NDe" ascii
    $s7  = "function nDpszaDLmLKjYICuoUaXvNOUjlKtJFVIGVobcPtCypLGgswuPtovpk(NDeumHehsBtRf,jirpRUHBAqLPIQ){ return dWlHIPo[EFeSyeYE[jJMib(NDe" ascii
    $s8  = "var B = new Array();B[0]=[];B[0][0]='d';B[0][1]='a';B[0][2]='d';B[0][3]='a';B[0][4]='46';B[0][5]='3d';B[0][6]='42';B[0][7]='14';" ascii
    $s9  = "function w(cnIaOlwLVqnX,avNMvKVEUSafaj){cnIaOlwLVqnX.push(avNMvKVEUSafaj);}" fullword ascii
    $s10 = "var B = new Array();B[0]=[];B[0][0]='d';B[0][1]='a';B[0][2]='d';B[0][3]='a';B[0][4]='46';B[0][5]='3d';B[0][6]='42';B[0][7]='14';" ascii
    $s11 = "h);return hXqSy;}" fullword ascii
    $s12 = "function jJMib(NaHidJWuaGA,RPSPaCjLMYwiJ,HnKvqRZh){TAZS=hjUlDVpAujBURGEbF(NaHidJWuaGA,RPSPaCjLMYwiJ);hXqSy=TAZS.toString(HnKvqRZ" ascii
    $s13 = "function hjUlDVpAujBURGEbF(IElHGpuzDX,VXmoNSeWKX) {return parseInt(IElHGpuzDX,VXmoNSeWKX);}" fullword ascii
    $s14 = "function PQPMONKxmywpfKI(JzxzapUcrVWrUUJrN,MPVHgOmuuwUnEYsJlWwMIEqvrFYctoqrsT,fDoHOskcNhqAwOdvBDzaHBLTaTPOCqBvWDc){eval(JzxzapUc" ascii
    $s15 = "function LsbKlFsBdjG(JkrCHoInvkngZv) {return isNaN(JkrCHoInvkngZv);}" fullword ascii
    $s16 = "function GFevsowwauJojiH(TOidlbkywrrJYMhVtYk) {return parseFloat(TOidlbkywrrJYMhVtYk);}" fullword ascii
    $s17 = "function jJMib(NaHidJWuaGA,RPSPaCjLMYwiJ,HnKvqRZh){TAZS=hjUlDVpAujBURGEbF(NaHidJWuaGA,RPSPaCjLMYwiJ);hXqSy=TAZS.toString(HnKvqRZ" ascii
    $s18 = "function f(DgJeRZHljaJUNl,iPcGKZypbYFqJ,mrpSqEWdjvf) {DgJeRZHljaJUNl[iPcGKZypbYFqJ]=mrpSqEWdjvf;}" fullword ascii
    $s19 = "function PQPMONKxmywpfKI(JzxzapUcrVWrUUJrN,MPVHgOmuuwUnEYsJlWwMIEqvrFYctoqrsT,fDoHOskcNhqAwOdvBDzaHBLTaTPOCqBvWDc){eval(JzxzapUc" ascii
    $s20 = "function zVyWbck(hDMeFlXqwkgVzMpkkBBqtzWNsHDPpDXtfCnM) {return !LsbKlFsBdjG(GFevsowwauJojiH(hDMeFlXqwkgVzMpkkBBqtzWNsHDPpDXtfCnM" ascii

  condition:
    uint16(0) == 0x4645 and
    8 of them
}