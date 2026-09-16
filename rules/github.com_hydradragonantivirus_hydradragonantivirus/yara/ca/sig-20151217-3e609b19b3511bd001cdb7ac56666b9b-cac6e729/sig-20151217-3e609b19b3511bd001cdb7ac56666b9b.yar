rule sig_20151217_3e609b19b3511bd001cdb7ac56666b9b {
  meta:
    description = "datamaliciousorder - file 20151217_3e609b19b3511bd001cdb7ac56666b9b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93c61f712b5b89fcad494304951e4ce22a81873f84653f634a5203b8661c0d83"

  strings:
    $s1  = "Math.cos(132), 2) - 1)));} LmPvloVrE[olHLdBWfxoV]++;}olHLdBWfxoV++;} return tpnUxSzzQtU}" fullword ascii
    $s2  = "th.pow(Math.cos(273), 2) - 1)); while(true) { if(LmPvloVrE[olHLdBWfxoV] > OyYtJ[olHLdBWfxoV].length-(80+672)/752) { break; } if " ascii
    $s3  = ") - 1));while(true){if (olHLdBWfxoV >= (4386+216)/767){break;}LmPvloVrE[olHLdBWfxoV]=Math.round((Math.pow(Math.sin(273), 2) + Ma" ascii
    $s4  = "function KqLmtVpCvoJVZOuev(OyYtJ){tpnUxSzzQtU= '';olHLdBWfxoV=Math.round((Math.pow(Math.sin(382), 2) + Math.pow(Math.cos(382), 2" ascii
    $s5  = "function KqLmtVpCvoJVZOuev(OyYtJ){tpnUxSzzQtU= '';olHLdBWfxoV=Math.round((Math.pow(Math.sin(382), 2) + Math.pow(Math.cos(382), 2" ascii
    $s6  = "function GSuPzngLbSIwCSuDmorbOnoENzQjiXIhPbZtyjENLoONVOsaIXnvPy(WdeVknBingDUy,RtNntNTbisHtdI){ return MlgyVmN[BjdLYWXX[HkZhv(Wde" ascii
    $s7  = "function TogBtlU(HTxItxrljdkDDMCFxpDnqKqAdidMYveRWvGV) {return !waVepIoSatu(DopFxIxCmMumdUc(HTxItxrljdkDDMCFxpDnqKqAdidMYveRWvGV" ascii
    $s8  = "function GSuPzngLbSIwCSuDmorbOnoENzQjiXIhPbZtyjENLoONVOsaIXnvPy(WdeVknBingDUy,RtNntNTbisHtdI){ return MlgyVmN[BjdLYWXX[HkZhv(Wde" ascii
    $s9  = "var b = new Array();b[0]=[];b[0][0]='d';b[0][1]='a';b[0][2]='d';b[0][3]='a';b[0][4]='46';b[0][5]='3d';b[0][6]='42';b[0][7]='14';" ascii
    $s10 = "var b = new Array();b[0]=[];b[0][0]='d';b[0][1]='a';b[0][2]='d';b[0][3]='a';b[0][4]='46';b[0][5]='3d';b[0][6]='42';b[0][7]='14';" ascii
    $s11 = "function JkGEHInLjsyl(ACpufntUcPJzf) {return isFinite(ACpufntUcPJzf);}" fullword ascii
    $s12 = "function waVepIoSatu(dmcjQIkHnnSxpj) {return isNaN(dmcjQIkHnnSxpj);}" fullword ascii
    $s13 = "function TogBtlU(HTxItxrljdkDDMCFxpDnqKqAdidMYveRWvGV) {return !waVepIoSatu(DopFxIxCmMumdUc(HTxItxrljdkDDMCFxpDnqKqAdidMYveRWvGV" ascii
    $s14 = "function R(xNipzjvQGuud,lKlpxyfaaArhuK){xNipzjvQGuud.push(lKlpxyfaaArhuK);}" fullword ascii
    $s15 = "function pSUdXvHOFIeVzSk(dYiSPSvOzQDjsYkVG,VIVKIhgBvRZauiQFkqgKQXYUKiPSKzKSvn,UJTGKmdfMAZgLAzQrlQkazwYFMfobnHDIEU){eval(dYiSPSvO" ascii
    $s16 = "function fCqDNNolVZfKetDJb(ZnIUNwVuIl,vxOBElqJht) {return parseInt(ZnIUNwVuIl,vxOBElqJht);}" fullword ascii
    $s17 = "function pSUdXvHOFIeVzSk(dYiSPSvOzQDjsYkVG,VIVKIhgBvRZauiQFkqgKQXYUKiPSKzKSvn,UJTGKmdfMAZgLAzQrlQkazwYFMfobnHDIEU){eval(dYiSPSvO" ascii
    $s18 = "function DopFxIxCmMumdUc(GPKkbQcjFDGuKrBQXTr) {return parseFloat(GPKkbQcjFDGuKrBQXTr);}" fullword ascii
    $s19 = "function HkZhv(WkPQRfgeUqx,rtjHjTRmoDPzq,QfxXjbDG){AJQo=fCqDNNolVZfKetDJb(WkPQRfgeUqx,rtjHjTRmoDPzq);dFfYS=AJQo.toString(QfxXjbD" ascii
    $s20 = "function k(BDhxhKBgtZweMG,KdqdFAjfRQorF,ojfYRdWBLkz) {BDhxhKBgtZweMG[KdqdFAjfRQorF]=ojfYRdWBLkz;}" fullword ascii

  condition:
    uint16(0) == 0x6a42 and
    8 of them
}