rule sig_20151208_2a324e541d8c7af1c9853c84a3010d35 {
  meta:
    description = "datamaliciousorder - file 20151208_2a324e541d8c7af1c9853c84a3010d35.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1139069bf8439712d183d14a413fce239a86a2115e74a778884c387ddebd2330"

  strings:
    $s1  = "function Xvdnwof(JphMbIYuvnernDmLeFUAlsiZJUJSnWZedkCB) {return !isNaN(parseFloat(JphMbIYuvnernDmLeFUAlsiZJUJSnWZedkCB)) && isFin" ascii
    $s2  = "function Xvdnwof(JphMbIYuvnernDmLeFUAlsiZJUJSnWZedkCB) {return !isNaN(parseFloat(JphMbIYuvnernDmLeFUAlsiZJUJSnWZedkCB)) && isFin" ascii
    $s3  = "function EMwrVKusewzwsidoSGClhTnOMQnZmEOQADUcNLYYfBpFSQCKHfpJcv(zkTckKAcGNRei,ntlKnIIslXirfc){ return NutxJVchPlwxM[rFzZx(zkTckK" ascii
    $s4  = "push(\"46\");k.push(\"111\");k.push(\"112\");k.push(\"101\");k.push(\"110\");k.push(\"40\");k.push(\"41\");k.push(\"59\");k.push" ascii
    $s5  = "function aDpzRqTqWuC(SOBdzOnE,onfoXZ){return SOBdzOnE.split(onfoXZ)}" fullword ascii
    $s6  = "push(\"32\");n.push(\"61\");n.push(\"32\");n.push(\"53\");n.push(\"57\");n.push(\"50\");n.push(\"56\");n.push(\"49\");n.push(\"5" ascii
    $s7  = "TGakcK)}function rFzZx(iIjjpFXyhhr,IOGHLKNnYyLdJ,iqdrwvtE){Vmvl=parseInt(iIjjpFXyhhr,IOGHLKNnYyLdJ);egDQo=Vmvl.toString(iqdrwvtE" ascii
    $s8  = ");return egDQo;}function zMeLCLmAHWCTDqM(aIFWXKpbxlDAHhADh){eval(aIFWXKpbxlDAHhADh)}" fullword ascii
    $s9  = "function tSrmkUomtypVyBOfP(mCNwB){IVQYnvMeFeq= '';for(GMipEAOzgQk=(-804+804)/112; GMipEAOzgQk < (1218+388)/803; GMipEAOzgQk++) {" ascii
    $s10 = "push(\"61\");k.push(\"32\");k.push(\"72\");k.push(\"59\");k.push(\"32\");k.push(\"98\");k.push(\"114\");k.push(\"101\");k.push(" ascii
    $s11 = "var NutxJVchPlwxM=[];for(lTGakcK=(-591+591)/425;lTGakcK<(123024+496)/965;lTGakcK++){NutxJVchPlwxM[lTGakcK]=String.fromCharCode(l" ascii
    $s12 = "push(\"9\");k.push(\"32\");k.push(\"13\");k.push(\"10\");k.push(\"32\");k.push(\"32\");k.push(\"32\");k.push(\"32\");k.push(\"85" ascii
    $s13 = "FHMFkvrAK[GMipEAOzgQk]=(-709+709)/463; while(true) { if(FHMFkvrAK[GMipEAOzgQk] > mCNwB[GMipEAOzgQk].length-(537+282)/819) { brea" ascii
    $s14 = "function tSrmkUomtypVyBOfP(mCNwB){IVQYnvMeFeq= '';for(GMipEAOzgQk=(-804+804)/112; GMipEAOzgQk < (1218+388)/803; GMipEAOzgQk++) {" ascii
    $s15 = "push(\"75\");k.push(\"119\");k.push(\"80\");k.push(\"73\");k.push(\"122\");k.push(\"101\");k.push(\"43\");k.push(\"47\");k.push(" ascii
    $s16 = "function EMwrVKusewzwsidoSGClhTnOMQnZmEOQADUcNLYYfBpFSQCKHfpJcv(zkTckKAcGNRei,ntlKnIIslXirfc){ return NutxJVchPlwxM[rFzZx(zkTckK" ascii
    $s17 = "push(\"106\");n.push(\"101\");n.push(\"99\");n.push(\"116\");n.push(\"40\");n.push(\"34\");n.push(\"77\");n.push(\"83\");n.push(" ascii
    $s18 = "++;}} return IVQYnvMeFeq}" fullword ascii
    $s19 = "push(\"42\");k.push(\"47\");k.push(\"34\");k.push(\"46\");k.push(\"101\");k.push(\"120\");k.push(\"101\");k.push(\"34\");k.push(" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}