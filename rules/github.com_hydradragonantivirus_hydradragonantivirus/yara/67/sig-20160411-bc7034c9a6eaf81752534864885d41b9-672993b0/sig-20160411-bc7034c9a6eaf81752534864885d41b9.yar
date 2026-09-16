rule sig_20160411_bc7034c9a6eaf81752534864885d41b9 {
  meta:
    description = "datamaliciousorder - file 20160411_bc7034c9a6eaf81752534864885d41b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1055676f109b0d563928086cae2b8c18de7bcb319ea8e19bcae2c476438e4126"

  strings:
    $s1  = "var sT = true  , XiGm = LIz[7] + LIz[9] + LIz[11];" fullword ascii
    $s2  = "return IqevwqB[0] + IqevwqB[2] + IqevwqB[4] + \".F\" + IqevwqB[7] + IqevwqB[9] + IqevwqB[12] + IqevwqB[14];" fullword ascii
    $s3  = "var LIz = (\"2.XMLHTTP LmcFysz wNbNQ XML ream St MBAUhxhw AD lbvoNoO O jzNw D\").split(\" \");" fullword ascii
    $s4  = "rcdn.open(xlSQx,ostDW,false);" fullword ascii
    $s5  = "NWHtG += HiNCH;" fullword ascii
    $s6  = "return NWHtG;" fullword ascii
    $s7  = "return \"cRppReSgUtDHlX\";" fullword ascii
    $s8  = "function bBIjh(brw,ZFcQY) {" fullword ascii
    $s9  = "function OidA(nBimQ) {" fullword ascii
    $s10 = "eval(function(p,a,c,k,e,d){e=function(c){return c};if(!\"\".replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d" ascii
    $s11 = "function AwnmPqvSZ(IgQOFXVOAsP) {" fullword ascii
    $s12 = "if (E >= OdoJq.length) {break;}" fullword ascii
    $s13 = "return TEw.size;" fullword ascii
    $s14 = "function TDGRuoV(OxCR) {" fullword ascii
    $s15 = "return yWFvm.status;" fullword ascii
    $s16 = "function KRMMlVw(BnsL,vwARA) {" fullword ascii
    $s17 = "function fUgR(BhdfF) {" fullword ascii
    $s18 = "function iTHV(KbaKU,BGiTJ) {" fullword ascii
    $s19 = "var HiNCH = OdoJq.substring(E, E+(857-856));" fullword ascii
    $s20 = "function GmAJ(VCxyc,ostDW,xlSQx) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}