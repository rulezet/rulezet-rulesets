rule sig_20160419_de50440a43423a967e1a81a5909c198a {
  meta:
    description = "datamaliciousorder - file 20160419_de50440a43423a967e1a81a5909c198a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c9d35945431a21a050495f82dae5a7392ec7ef2e8f2bbf5989c4e5ededa81fe"

  strings:
    $s1  = "return PBVZwnq[0] + PBVZwnq[2] + PBVZwnq[4] + \".F\" + PBVZwnq[7] + PBVZwnq[9] + PBVZwnq[12] + PBVZwnq[14];" fullword ascii
    $s2  = "var TH = true  , SaIB = ylp[7] + ylp[9] + ylp[11];" fullword ascii
    $s3  = "Pudx.open(MXhUH,loOqf,false);" fullword ascii
    $s4  = "var ylp = (\"2.XMLHTTP nesWcPG yTyNA XML ream St nfYOMoVc AD LlCrDjy O qPmb D\").split(\" \");" fullword ascii
    $s5  = "if(b>=p.length) {break;}" fullword ascii
    $s6  = "function qMbR(ZqMCT) {" fullword ascii
    $s7  = "function hUig(ImSHc,LUdgG) {" fullword ascii
    $s8  = "function OalK(kHIBF) {" fullword ascii
    $s9  = "function wLQaCEXzt(wmRpRbDIGed) {" fullword ascii
    $s10 = "function kJWg(fQAmj) {" fullword ascii
    $s11 = "function aCJPXsYP(HZsk) {" fullword ascii
    $s12 = "function peJm(qaSsg,gpMBm) {" fullword ascii
    $s13 = "function hPeg(SUcIJ) {" fullword ascii
    $s14 = "eval(function(p,a,c,k,e,d){e=function(c){return c};if(!\"\".replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d" ascii
    $s15 = "return kHIBF.status;" fullword ascii
    $s16 = "function ZfkY(LxrNT) {" fullword ascii
    $s17 = "return SQNz[tIKaSjI[0]+tIKaSjI[1]];" fullword ascii
    $s18 = "function PvyW(TYSqk,loOqf,MXhUH) {" fullword ascii
    $s19 = "LDQ = b; break; " fullword ascii
    $s20 = "function aGAsO(ykUXSUNZ,srKk) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}