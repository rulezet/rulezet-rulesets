rule sig_20151210_ecee735c5a31972f8a34354768fe6675 {
  meta:
    description = "datamaliciousorder - file 20151210_ecee735c5a31972f8a34354768fe6675.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a405947607cde60b2f30ea17d7fe1ad9fdf1be5c0713cecbb43e0360442aea4"

  strings:
    $s1  = "function LDLXeCq(KTjADszYkCyCoNITcDvaEZswINegSDWhZyrd) {return !isNaN(parseFloat(KTjADszYkCyCoNITcDvaEZswINegSDWhZyrd)) && isFin" ascii
    $s2  = "function LDLXeCq(KTjADszYkCyCoNITcDvaEZswINegSDWhZyrd) {return !isNaN(parseFloat(KTjADszYkCyCoNITcDvaEZswINegSDWhZyrd)) && isFin" ascii
    $s3  = "function usjjolBHdWhuoqanwTDXLSCWlUdTYVryvlmjMCIlFfQYrlLAGzTvPa(DqvSeawXGAbzX,VmveGSixtofIjT){ return evHCtsDHkaxsp[vGPFm(DqvSea" ascii
    $s4  = ";}} return GbuICZHVjjH}" fullword ascii
    $s5  = "function qsZNNsQjkub(yaRPpAXG,ZhnVXC){return yaRPpAXG.split(ZhnVXC)}" fullword ascii
    $s6  = "EQsSRLi=(-971+971)/866;while(true){if(EQsSRLi>=(94423+425)/741){break;}evHCtsDHkaxsp[EQsSRLi]=String.fromCharCode(EQsSRLi);EQsSR" ascii
    $s7  = "function usjjolBHdWhuoqanwTDXLSCWlUdTYVryvlmjMCIlFfQYrlLAGzTvPa(DqvSeawXGAbzX,VmveGSixtofIjT){ return evHCtsDHkaxsp[vGPFm(DqvSea" ascii
    $s8  = "function vGPFm(jpyKSJlaZsN,enCunCiZJFAdF,GzDOSKhM){PQAs=parseInt(jpyKSJlaZsN,enCunCiZJFAdF);FnIoc=PQAs.toString(GzDOSKhM);return" ascii
    $s9  = "EQsSRLi=(-971+971)/866;while(true){if(EQsSRLi>=(94423+425)/741){break;}evHCtsDHkaxsp[EQsSRLi]=String.fromCharCode(EQsSRLi);EQsSR" ascii
    $s10 = " FnIoc;}function QovEHErgSaCBzhy(NvvZJaDyFHhTcFqaU){eval(NvvZJaDyFHhTcFqaU)}" fullword ascii
    $s11 = "function vGPFm(jpyKSJlaZsN,enCunCiZJFAdF,GzDOSKhM){PQAs=parseInt(jpyKSJlaZsN,enCunCiZJFAdF);FnIoc=PQAs.toString(GzDOSKhM);return" ascii
    $s12 = "psYoojLX[RbkjSrePzxy]=(-422+422)/68; while(true) { if(mpsYoojLX[RbkjSrePzxy] > kqgVG[RbkjSrePzxy].length-(404+427)/831) { break;" ascii
    $s13 = "function ZaMKXfMIotcaPNAvH(kqgVG){GbuICZHVjjH= '';for(RbkjSrePzxy=(-920+920)/257; RbkjSrePzxy < (724+804)/764; RbkjSrePzxy++) {m" ascii
    $s14 = "function ZaMKXfMIotcaPNAvH(kqgVG){GbuICZHVjjH= '';for(RbkjSrePzxy=(-920+920)/257; RbkjSrePzxy < (724+804)/764; RbkjSrePzxy++) {m" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}