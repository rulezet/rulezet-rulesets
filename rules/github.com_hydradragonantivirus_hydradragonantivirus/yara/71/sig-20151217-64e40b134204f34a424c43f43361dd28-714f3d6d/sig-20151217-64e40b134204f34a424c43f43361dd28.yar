rule sig_20151217_64e40b134204f34a424c43f43361dd28 {
  meta:
    description = "datamaliciousorder - file 20151217_64e40b134204f34a424c43f43361dd28.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9459fd835bccfd939e944a928d21659dfcaec9ff58ff451533a493deda44bc5"

  strings:
    $s1  = "ath.cos(264), 2) - 1)));} gShSLbakq[vLGELYzQGzB]++;}vLGELYzQGzB++;} return bgDqSssPTSH}" fullword ascii
    $s2  = ") - 1));while(true){if (vLGELYzQGzB >= (5359+545)/984){break;}gShSLbakq[vLGELYzQGzB]=Math.round((Math.pow(Math.sin(20), 2) + Mat" ascii
    $s3  = "function lVcqMkdDyZnJJvUAV(kqclG){bgDqSssPTSH= '';vLGELYzQGzB=Math.round((Math.pow(Math.sin(470), 2) + Math.pow(Math.cos(470), 2" ascii
    $s4  = "h.pow(Math.cos(20), 2) - 1)); while(true) { if(gShSLbakq[vLGELYzQGzB] > kqclG[vLGELYzQGzB].length-(73+154)/227) { break; } if (F" ascii
    $s5  = "function lVcqMkdDyZnJJvUAV(kqclG){bgDqSssPTSH= '';vLGELYzQGzB=Math.round((Math.pow(Math.sin(470), 2) + Math.pow(Math.cos(470), 2" ascii
    $s6  = "function FQCGEDL(wNkWXZXArZmAJXBUtPhuwDjDrOswcwXrpRJG) {return !tkfoRMDBqMq(XHQeMNzTjLylhhh(wNkWXZXArZmAJXBUtPhuwDjDrOswcwXrpRJG" ascii
    $s7  = "var K = new Array();K[0]=[];K[0][0]='d';K[0][1]='a';K[0][2]='d';K[0][3]='a';K[0][4]='46';K[0][5]='3d';K[0][6]='42';K[0][7]='14';" ascii
    $s8  = "function TbppNKTFZrKV(sClexJJOMIgSD) {return isFinite(sClexJJOMIgSD);}" fullword ascii
    $s9  = "function YUnOETRYpMFtDXlBdXquCBUzOGWOxfIUDsQQukMoqsrcGdlhfIGKPg(MDlzVbmFkgWCL,hjevfNbcDjdymU){ return fUfVBcr[yPwhRwSs[KqXUN(MDl" ascii
    $s10 = "function FQCGEDL(wNkWXZXArZmAJXBUtPhuwDjDrOswcwXrpRJG) {return !tkfoRMDBqMq(XHQeMNzTjLylhhh(wNkWXZXArZmAJXBUtPhuwDjDrOswcwXrpRJG" ascii
    $s11 = "var K = new Array();K[0]=[];K[0][0]='d';K[0][1]='a';K[0][2]='d';K[0][3]='a';K[0][4]='46';K[0][5]='3d';K[0][6]='42';K[0][7]='14';" ascii
    $s12 = "function MqxXqFaYVASlzQy(LoQauwaxcxltXzqqR,xIbHLKGNtaqhuhaOiZVTwVqXEeqNHqxZyH,ZhHDTSJCiBOmWBPHhZEZWdySerEcxGaYYjX){eval(LoQauwax" ascii
    $s13 = "function YUnOETRYpMFtDXlBdXquCBUzOGWOxfIUDsQQukMoqsrcGdlhfIGKPg(MDlzVbmFkgWCL,hjevfNbcDjdymU){ return fUfVBcr[yPwhRwSs[KqXUN(MDl" ascii
    $s14 = "function YIgVFckeCPvmGQzIO(AARuryERzP,znsKByulWV) {return parseInt(AARuryERzP,znsKByulWV);}" fullword ascii
    $s15 = "function KqXUN(QHWikYJcWVW,LROlSkKxmoVgC,Otmubpcv){fCed=YIgVFckeCPvmGQzIO(QHWikYJcWVW,LROlSkKxmoVgC);EsNPK=fCed.toString(Otmubpc" ascii
    $s16 = "function KqXUN(QHWikYJcWVW,LROlSkKxmoVgC,Otmubpcv){fCed=YIgVFckeCPvmGQzIO(QHWikYJcWVW,LROlSkKxmoVgC);EsNPK=fCed.toString(Otmubpc" ascii
    $s17 = "v);return EsNPK;}" fullword ascii
    $s18 = "function v(wRpcSJEHgPuF,VWnxvoYbJTXdhw){wRpcSJEHgPuF.push(VWnxvoYbJTXdhw);}" fullword ascii
    $s19 = "function XHQeMNzTjLylhhh(UsxpgMrxqyqEinphlcQ) {return parseFloat(UsxpgMrxqyqEinphlcQ);}" fullword ascii
    $s20 = "function MqxXqFaYVASlzQy(LoQauwaxcxltXzqqR,xIbHLKGNtaqhuhaOiZVTwVqXEeqNHqxZyH,ZhHDTSJCiBOmWBPHhZEZWdySerEcxGaYYjX){eval(LoQauwax" ascii

  condition:
    uint16(0) == 0x5079 and
    8 of them
}