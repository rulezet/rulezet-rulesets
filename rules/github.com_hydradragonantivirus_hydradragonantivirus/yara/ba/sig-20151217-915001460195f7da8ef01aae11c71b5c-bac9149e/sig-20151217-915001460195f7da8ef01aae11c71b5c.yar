rule sig_20151217_915001460195f7da8ef01aae11c71b5c {
  meta:
    description = "datamaliciousorder - file 20151217_915001460195f7da8ef01aae11c71b5c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3ba9a111abc07b3f0611a64a9323704fb738f8c81873a10f0b84c1667a21c34"

  strings:
    $s1  = "function kSTOXhkuvFYZJfVxx(JSzIY){QBRaBCTBXUG= '';FBQFDbUWDze=Math.round((Math.pow(Math.sin(512), 2) + Math.pow(Math.cos(512), 2" ascii
    $s2  = "th.pow(Math.cos(187), 2) - 1)); while(true) { if(ehxHmTeBy[FBQFDbUWDze] > JSzIY[FBQFDbUWDze].length-(723+43)/766) { break; } if " ascii
    $s3  = "ow(Math.cos(240), 2) - 1)));} ehxHmTeBy[FBQFDbUWDze]++;}FBQFDbUWDze++;} return QBRaBCTBXUG}" fullword ascii
    $s4  = ") - 1));while(true){if (FBQFDbUWDze >= (2592+366)/493){break;}ehxHmTeBy[FBQFDbUWDze]=Math.round((Math.pow(Math.sin(187), 2) + Ma" ascii
    $s5  = "function kSTOXhkuvFYZJfVxx(JSzIY){QBRaBCTBXUG= '';FBQFDbUWDze=Math.round((Math.pow(Math.sin(512), 2) + Math.pow(Math.cos(512), 2" ascii
    $s6  = "function mgGwaqeuzGwgxPwwe(wQDIxZhUxj,IvIrCjTbsr) {return parseInt(wQDIxZhUxj,IvIrCjTbsr);}" fullword ascii
    $s7  = "function LflForE(OvPEGMLnazRvqEmMeikPSHPZJPDFQxjyWDcW) {return !QDsQqelFeal(mmREzunaFOMjlLG(OvPEGMLnazRvqEmMeikPSHPZJPDFQxjyWDcW" ascii
    $s8  = "var L = new Array();L[0]=[];L[0][0]='d';L[0][1]='a';L[0][2]='d';L[0][3]='a';L[0][4]='46';L[0][5]='3d';L[0][6]='42';L[0][7]='14';" ascii
    $s9  = "function p(qOBtfsjMHILpcc,UOfyefUoGrwKV,VvElkieelGz) {qOBtfsjMHILpcc[UOfyefUoGrwKV]=VvElkieelGz;}" fullword ascii
    $s10 = "function wFwNnnXBgcstGLJ(jnjvcchZLPljnXZqN,ZfgEDhXVyPOIxgbVfAUfkfTthrDrRtEYaw,fIjYDWuFedsPnxNOSPiqKGtNVoOaNFCooxw){eval(jnjvcchZ" ascii
    $s11 = "function mmREzunaFOMjlLG(zENgHsmYHCGAVeypUnI) {return parseFloat(zENgHsmYHCGAVeypUnI);}" fullword ascii
    $s12 = "var L = new Array();L[0]=[];L[0][0]='d';L[0][1]='a';L[0][2]='d';L[0][3]='a';L[0][4]='46';L[0][5]='3d';L[0][6]='42';L[0][7]='14';" ascii
    $s13 = "function CkgXVtbulfYvgWAVJzUSpFHbiChNsQcbdDAYUToKgDabxxJepWSzVA(UmQVqaCZVJYZa,uHbmhKyWazPPVe){ return YhKFXJo[xiWqeVnq[qzNwK(UmQ" ascii
    $s14 = "function qzNwK(suWFEgIyhFL,JGXUYkGkaoSYZ,XAWWryli){zMIo=mgGwaqeuzGwgxPwwe(suWFEgIyhFL,JGXUYkGkaoSYZ);BIEHi=zMIo.toString(XAWWryl" ascii
    $s15 = "function qzNwK(suWFEgIyhFL,JGXUYkGkaoSYZ,XAWWryli){zMIo=mgGwaqeuzGwgxPwwe(suWFEgIyhFL,JGXUYkGkaoSYZ);BIEHi=zMIo.toString(XAWWryl" ascii
    $s16 = "function CkgXVtbulfYvgWAVJzUSpFHbiChNsQcbdDAYUToKgDabxxJepWSzVA(UmQVqaCZVJYZa,uHbmhKyWazPPVe){ return YhKFXJo[xiWqeVnq[qzNwK(UmQ" ascii
    $s17 = "i);return BIEHi;}" fullword ascii
    $s18 = ",'n','s','V','U','=','z','G','W','y','O','U','Z','X',';','#','x','Q','Y',' ','2','6','+','{','Z','[','R','?','m','2',']',String." ascii
    $s19 = "function SnXDdoFSaNkB(ouCbvBsRjPClM) {return isFinite(ouCbvBsRjPClM);}" fullword ascii
    $s20 = "function QDsQqelFeal(HntpCgfDzVBmMH) {return isNaN(HntpCgfDzVBmMH);}" fullword ascii

  condition:
    uint16(0) == 0x6978 and
    8 of them
}