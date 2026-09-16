rule sig_20151217_eafe57c338e1103d4a3f54633941116c {
  meta:
    description = "datamaliciousorder - file 20151217_eafe57c338e1103d4a3f54633941116c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ba4ddf84796abdcd68c166c7f15dd5452b53ae3fbbfbb239017c496839d28d2"

  strings:
    $s1  = "h.pow(Math.cos(501), 2) - 1)); while(true) { if(PFqTDWbpS[xHnRLXjedjN] > khfGw[xHnRLXjedjN].length-(-536+794)/258) { break; } if" ascii
    $s2  = ") - 1));while(true){if (xHnRLXjedjN >= (987+969)/326){break;}PFqTDWbpS[xHnRLXjedjN]=Math.round((Math.pow(Math.sin(501), 2) + Mat" ascii
    $s3  = "function MPHloDbrDQgSujMWW(khfGw){bOiHGEOZMth= '';xHnRLXjedjN=Math.round((Math.pow(Math.sin(678), 2) + Math.pow(Math.cos(678), 2" ascii
    $s4  = "w(Math.cos(790), 2) - 1)));} PFqTDWbpS[xHnRLXjedjN]++;}xHnRLXjedjN++;} return bOiHGEOZMth}" fullword ascii
    $s5  = "function MPHloDbrDQgSujMWW(khfGw){bOiHGEOZMth= '';xHnRLXjedjN=Math.round((Math.pow(Math.sin(678), 2) + Math.pow(Math.cos(678), 2" ascii
    $s6  = "function yKhOxvX(GhFDTdoTMsuNdukSzTgNgnOozMCoAtpIcqKJ) {return !BSeoyyAVZRJ(urUETDFXxTZzALP(GhFDTdoTMsuNdukSzTgNgnOozMCoAtpIcqKJ" ascii
    $s7  = "var B = new Array();B[0]=[];B[0][0]='d';B[0][1]='a';B[0][2]='d';B[0][3]='a';B[0][4]='46';B[0][5]='3d';B[0][6]='42';B[0][7]='14';" ascii
    $s8  = "function urUETDFXxTZzALP(JtEKqAcsGoFzEjiQPpP) {return parseFloat(JtEKqAcsGoFzEjiQPpP);}" fullword ascii
    $s9  = "var B = new Array();B[0]=[];B[0][0]='d';B[0][1]='a';B[0][2]='d';B[0][3]='a';B[0][4]='46';B[0][5]='3d';B[0][6]='42';B[0][7]='14';" ascii
    $s10 = "function O(fsdeSSeOcFlx,BsfQgTWMJcDwmp){fsdeSSeOcFlx.push(BsfQgTWMJcDwmp);}" fullword ascii
    $s11 = "function vRbUrewBaqZQEvcxLwlRFWrHrsPaMHYSrAbUyNjArXtZpGDNUtjFta(kAYEVKKSLDRtX,qpQNmlDPMDHBhF){ return hYkfFRb[yrZRFFwB[vpkOn(kAY" ascii
    $s12 = "function vRbUrewBaqZQEvcxLwlRFWrHrsPaMHYSrAbUyNjArXtZpGDNUtjFta(kAYEVKKSLDRtX,qpQNmlDPMDHBhF){ return hYkfFRb[yrZRFFwB[vpkOn(kAY" ascii
    $s13 = "function BSeoyyAVZRJ(hzocYCvSgoWeNb) {return isNaN(hzocYCvSgoWeNb);}" fullword ascii
    $s14 = "t);return uRaLF;}" fullword ascii
    $s15 = "function YIPgWwJonNJlEMH(NTzHeCdnhQbgtDdne,HUSuXNpVeFtVqWjcXLofUDjWAXyuzTRUOq,CqMvSqRZAAHawogAAuVdhGlWtBQIuNnPsTV){eval(NTzHeCdn" ascii
    $s16 = "function YKDmsNsGuUNUmeFOf(XeUgpSxfuV,JlhZVguARV) {return parseInt(XeUgpSxfuV,JlhZVguARV);}" fullword ascii
    $s17 = "function yKhOxvX(GhFDTdoTMsuNdukSzTgNgnOozMCoAtpIcqKJ) {return !BSeoyyAVZRJ(urUETDFXxTZzALP(GhFDTdoTMsuNdukSzTgNgnOozMCoAtpIcqKJ" ascii
    $s18 = "function vpkOn(hkJhmSkPRYP,twdSuOjzfLydi,XNVsqUmt){ewnD=YKDmsNsGuUNUmeFOf(hkJhmSkPRYP,twdSuOjzfLydi);uRaLF=ewnD.toString(XNVsqUm" ascii
    $s19 = "function YIPgWwJonNJlEMH(NTzHeCdnhQbgtDdne,HUSuXNpVeFtVqWjcXLofUDjWAXyuzTRUOq,CqMvSqRZAAHawogAAuVdhGlWtBQIuNnPsTV){eval(NTzHeCdn" ascii
    $s20 = "function vpkOn(hkJhmSkPRYP,twdSuOjzfLydi,XNVsqUmt){ewnD=YKDmsNsGuUNUmeFOf(hkJhmSkPRYP,twdSuOjzfLydi);uRaLF=ewnD.toString(XNVsqUm" ascii

  condition:
    uint16(0) == 0x7279 and
    8 of them
}