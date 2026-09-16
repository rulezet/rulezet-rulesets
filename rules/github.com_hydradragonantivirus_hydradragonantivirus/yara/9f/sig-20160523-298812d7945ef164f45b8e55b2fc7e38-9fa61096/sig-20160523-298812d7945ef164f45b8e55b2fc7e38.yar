rule sig_20160523_298812d7945ef164f45b8e55b2fc7e38 {
  meta:
    description = "datamaliciousorder - file 20160523_298812d7945ef164f45b8e55b2fc7e38.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a66e41a7f14a3d3343deb3c106c92542c4d9c8caf537068e0b5bac1fea78b9f9"

  strings:
    $s1  = "function yYDoPtwe(zPLUJ) {var yIZXNoDO=HPZSOlMbbDaLVhCF[13];for(var CuUgd=0;CuUgd<zPLUJ;CuUgd++){umSsY+=yIZXNoDO.charAt(Math.flo" ascii
    $s2  = "function iPSeWZNOkT() {return/*bsSYWTLpBJZhFxJYeCfVGVYLNbfOAhqCtysITCPNJjyimxjFckUiDqDHOqYqyxWBhhPUWBjOWoyEOtSJKMhzKVtvEpMoUhdeR" ascii
    $s3  = "function tvvSqLopBm(FLmPPAOE,vhQskbOGbRof) {FLmPPAOE.Run(vhQskbOGbRof, 0x1, 0x0);}" fullword ascii
    $s4  = "function yYDoPtwe(zPLUJ) {var yIZXNoDO=HPZSOlMbbDaLVhCF[13];for(var CuUgd=0;CuUgd<zPLUJ;CuUgd++){umSsY+=yIZXNoDO.charAt(Math.flo" ascii
    $s5  = "or(Math.random()*yIZXNoDO.length));}return umSsY;}" fullword ascii
    $s6  = "function anHJW(TdAkwo){return new ActiveXObject(TdAkwo);}" fullword ascii
    $s7  = "function XIlnc(ChxtjcYS,urJjuY,lsrEUkPGz){lyqYp=ChxtjcYS.split(lsrEUkPGz);DhfbQlW = HPZSOlMbbDaLVhCF[12];for(MVyLFqwF=0;MVyLFqwF" ascii
    $s8  = "function RZvD(cxaGIp,mVVUqny){nMiD = HPZSOlMbbDaLVhCF[10].split(HPZSOlMbbDaLVhCF[11]);mVVUqny.open(nMiD[0]+nMiD[2]+nMiD[3], cxaG" ascii
    $s9  = "function ndnPE(pHyVMOII,ctGyR,GoxwXIiKID){yALD(pHyVMOII);YcCkqMEg(pHyVMOII);XyJHZHG(pHyVMOII,ctGyR);uNHoylKrh(pHyVMOII);INMh(pHy" ascii
    $s10 = "function ndnPE(pHyVMOII,ctGyR,GoxwXIiKID){yALD(pHyVMOII);YcCkqMEg(pHyVMOII);XyJHZHG(pHyVMOII,ctGyR);uNHoylKrh(pHyVMOII);INMh(pHy" ascii
    $s11 = "Ip, false);mVVUqny.send();}" fullword ascii
    $s12 = "function jXleZDa(Dwdra) {Dwdra.close();}" fullword ascii
    $s13 = "function HhcyXwl(){return Math.random();}" fullword ascii
    $s14 = "function RZvD(cxaGIp,mVVUqny){nMiD = HPZSOlMbbDaLVhCF[10].split(HPZSOlMbbDaLVhCF[11]);mVVUqny.open(nMiD[0]+nMiD[2]+nMiD[3], cxaG" ascii
    $s15 = "function XIlnc(ChxtjcYS,urJjuY,lsrEUkPGz){lyqYp=ChxtjcYS.split(lsrEUkPGz);DhfbQlW = HPZSOlMbbDaLVhCF[12];for(MVyLFqwF=0;MVyLFqwF" ascii
    $s16 = "function zNrLdCZYGRsYe() {iPSeWZNOkT().Sleep(2445477-508);}" fullword ascii
    $s17 = "function iPSeWZNOkT() {return/*bsSYWTLpBJZhFxJYeCfVGVYLNbfOAhqCtysITCPNJjyimxjFckUiDqDHOqYqyxWBhhPUWBjOWoyEOtSJKMhzKVtvEpMoUhdeR" ascii
    $s18 = "function uNHoylKrh(omyMTy) {var AOFprPqCzl=[];omyMTy.position=AOFprPqCzl.length*(3533969-446);}" fullword ascii
    $s19 = "function kfLBIG(TdAkwo){return TdAkwo.ExpandEnvironmentStrings(HPZSOlMbbDaLVhCF[9])}" fullword ascii
    $s20 = "function XyJHZHG(oaWG,YWSLq) {oaWG.write(YWSLq);}" fullword ascii

  condition:
    uint16(0) == 0x2027 and
    8 of them
}