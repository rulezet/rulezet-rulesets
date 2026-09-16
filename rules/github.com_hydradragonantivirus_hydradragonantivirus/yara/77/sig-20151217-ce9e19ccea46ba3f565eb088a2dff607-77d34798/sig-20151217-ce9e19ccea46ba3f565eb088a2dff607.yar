rule sig_20151217_ce9e19ccea46ba3f565eb088a2dff607 {
  meta:
    description = "datamaliciousorder - file 20151217_ce9e19ccea46ba3f565eb088a2dff607.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81b264a25ee146969999a04e9c8445905dc837abe60388b6d25505b938613932"

  strings:
    $s1  = "(Math.cos(220), 2) - 1)));} DPyQoujIg[jRTpYPctspF]++;}jRTpYPctspF++;} return fjLqewboKjC}" fullword ascii
    $s2  = ") - 1));while(true){if (jRTpYPctspF >= (4716+144)/810){break;}DPyQoujIg[jRTpYPctspF]=Math.round((Math.pow(Math.sin(344), 2) + Ma" ascii
    $s3  = "function dNlJIpDYObGrKotVQ(PQOyN){fjLqewboKjC= '';jRTpYPctspF=Math.round((Math.pow(Math.sin(525), 2) + Math.pow(Math.cos(525), 2" ascii
    $s4  = "th.pow(Math.cos(344), 2) - 1)); while(true) { if(DPyQoujIg[jRTpYPctspF] > PQOyN[jRTpYPctspF].length-(310+111)/421) { break; } if" ascii
    $s5  = "function dNlJIpDYObGrKotVQ(PQOyN){fjLqewboKjC= '';jRTpYPctspF=Math.round((Math.pow(Math.sin(525), 2) + Math.pow(Math.cos(525), 2" ascii
    $s6  = "function N(zPiRcZFaCyci,uzzPzFQYCvvfbQ){zPiRcZFaCyci.push(uzzPzFQYCvvfbQ);}" fullword ascii
    $s7  = "function gyjiXueijXZyAsv(YJtRFgcPahyUBZBrn,NoCogHZbrwdhFmwFlHVXdtIBOzPnhbXzwx,XLnfbYlPndRVvBQHFsPywUmJLUGBnOdkZdU){eval(YJtRFgcP" ascii
    $s8  = "function gyjiXueijXZyAsv(YJtRFgcPahyUBZBrn,NoCogHZbrwdhFmwFlHVXdtIBOzPnhbXzwx,XLnfbYlPndRVvBQHFsPywUmJLUGBnOdkZdU){eval(YJtRFgcP" ascii
    $s9  = "var c = new Array();c[0]=[];c[0][0]='d';c[0][1]='a';c[0][2]='d';c[0][3]='a';c[0][4]='46';c[0][5]='3d';c[0][6]='42';c[0][7]='14';" ascii
    $s10 = "var c = new Array();c[0]=[];c[0][0]='d';c[0][1]='a';c[0][2]='d';c[0][3]='a';c[0][4]='46';c[0][5]='3d';c[0][6]='42';c[0][7]='14';" ascii
    $s11 = "function XOGSRFSaJoQIPJlumsbFgtPOMEKliwXClZKTOORZSdFUaJLdmmriyQ(KAKYRAVjyiYCK,mYBucxavObGvgY){ return jULwwaf[jdLgEuxU[rBXyL(KAK" ascii
    $s12 = "function XOGSRFSaJoQIPJlumsbFgtPOMEKliwXClZKTOORZSdFUaJLdmmriyQ(KAKYRAVjyiYCK,mYBucxavObGvgY){ return jULwwaf[jdLgEuxU[rBXyL(KAK" ascii
    $s13 = "function lwEAiDUqqDgzlRbqW(XqqenJLfSZ,yprPUpneer) {return parseInt(XqqenJLfSZ,yprPUpneer);}" fullword ascii
    $s14 = "function rBXyL(eXmbPJDYhMN,wjhVRYxrblCgz,WTPhUzpE){eOwq=lwEAiDUqqDgzlRbqW(eXmbPJDYhMN,wjhVRYxrblCgz);HbAsj=eOwq.toString(WTPhUzp" ascii
    $s15 = "E);return HbAsj;}" fullword ascii
    $s16 = "function fVQHWjLzQav(lrUvsZpyeTgyNs) {return isNaN(lrUvsZpyeTgyNs);}" fullword ascii
    $s17 = "function usbzAEnKYJCt(irzOgxQfMrjfE) {return isFinite(irzOgxQfMrjfE);}" fullword ascii
    $s18 = "function rBXyL(eXmbPJDYhMN,wjhVRYxrblCgz,WTPhUzpE){eOwq=lwEAiDUqqDgzlRbqW(eXmbPJDYhMN,wjhVRYxrblCgz);HbAsj=eOwq.toString(WTPhUzp" ascii
    $s19 = "function t(pKgKgBBEwHgdMF,fGqlVbUMoJvwu,PxapaPqvVPG) {pKgKgBBEwHgdMF[fGqlVbUMoJvwu]=PxapaPqvVPG;}" fullword ascii
    $s20 = "function mmaLPko(HCJZSJUgUUybLeHhzLRwgjCOZpbRPgJSCgSx) {return !fVQHWjLzQav(VQLcAsnIBmwIunR(HCJZSJUgUUybLeHhzLRwgjCOZpbRPgJSCgSx" ascii

  condition:
    uint16(0) == 0x646a and
    8 of them
}