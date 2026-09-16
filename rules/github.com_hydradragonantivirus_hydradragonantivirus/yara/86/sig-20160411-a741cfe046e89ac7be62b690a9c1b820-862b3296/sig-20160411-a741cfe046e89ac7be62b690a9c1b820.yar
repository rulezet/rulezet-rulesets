rule sig_20160411_a741cfe046e89ac7be62b690a9c1b820 {
  meta:
    description = "datamaliciousorder - file 20160411_a741cfe046e89ac7be62b690a9c1b820.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b24e5fb52ca85908ce7fa0b10a7df2fdb9cd84bcae4aafd50b7fd18a8304b6a"

  strings:
    $s1  = "var wk = true  , PzKp = ZMA[7] + ZMA[9] + ZMA[11];" fullword ascii
    $s2  = "return viGQaen[0] + viGQaen[2] + viGQaen[4] + \".F\" + viGQaen[7] + viGQaen[9] + viGQaen[12] + viGQaen[14];" fullword ascii
    $s3  = "IWef.open(BbbrK,ACFmw,false);" fullword ascii
    $s4  = "function ftENM(kDaaIJqO,oDOn) {" fullword ascii
    $s5  = "function ktsY(JHNoo) {" fullword ascii
    $s6  = "return yWMkA.status;" fullword ascii
    $s7  = "return rSeglMZ;" fullword ascii
    $s8  = "if(Z>=Y.length) {break;}" fullword ascii
    $s9  = "return GXS[imhI[0]](FUkTs);" fullword ascii
    $s10 = "return bQSNGa[oREQ[421-421]]=416-416;" fullword ascii
    $s11 = "oAH = Z; break; " fullword ascii
    $s12 = "return Jhe.size;" fullword ascii
    $s13 = "function ittv(Xwjym) {" fullword ascii
    $s14 = "function XzNc(yWMkA) {" fullword ascii
    $s15 = "function UVNeBq(OFcc,yfseVA) {" fullword ascii
    $s16 = "function cwkV(Saqfm) {" fullword ascii
    $s17 = "eval(function(p,a,c,k,e,d){e=function(c){return c};if(!\"\".replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d" ascii
    $s18 = "function gHTB(avwSS) {" fullword ascii
    $s19 = "if (M >= Xwjym.length) {break;}" fullword ascii
    $s20 = "return QyNY[zEiouoK[0]+zEiouoK[1]];" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}