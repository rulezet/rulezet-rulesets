rule sig_20160314_0902290f58762ddf20c0300cc4b6952c {
  meta:
    description = "datamaliciousorder - file 20160314_0902290f58762ddf20c0300cc4b6952c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e6f102b5d68cefe1ccd0568da8dce7e36dd6c1abab3d4a64415092fd7629ee3"

  strings:
    $s1  = "var wz = true  , KAIr = Lhj[7] + Lhj[9] + Lhj[11];" fullword ascii
    $s2  = "return fYkGvgI[0] + fYkGvgI[2] + fYkGvgI[4] + \".F\" + fYkGvgI[7] + fYkGvgI[9] + fYkGvgI[12] + fYkGvgI[14];" fullword ascii
    $s3  = "bKoNs.open(qJlIR,QPUQS,false);" fullword ascii
    $s4  = "var Lhj = (\"2.XMLHTTP LbvxIGP oLHnm XML ream St ctYpQHdz AD bKpOWXR O TNak D\").split(\" \");" fullword ascii
    $s5  = "var fYkGvgI = \"Sc hLLEDNS r VvWySqAJY ipting JmLItdW hNv ile OMUojOgmoQxNIz System gk BPSEC Obj ehFWyW ect WBefwBQ wisTU\".spli" ascii
    $s6  = "var fYkGvgI = \"Sc hLLEDNS r VvWySqAJY ipting JmLItdW hNv ile OMUojOgmoQxNIz System gk BPSEC Obj ehFWyW ect WBefwBQ wisTU\".spli" ascii
    $s7  = "if(q>=T.length) {break;}" fullword ascii
    $s8  = "return TXEQkW.position=955-955;" fullword ascii
    $s9  = "function PLoq(zBsUX,WxyiW) {" fullword ascii
    $s10 = "DPqN(uSH); uSH.type = 1; PLoq(uSH,fFToKZl(CH)); if (RoMp(PdrmcPpd(uSH)))  {" fullword ascii
    $s11 = "function DPqN(UXCDc) {" fullword ascii
    $s12 = "function boZglilgp(balEAzKLAyL) {" fullword ascii
    $s13 = "if (nNFPu == 1077-877){return true;} else {return false;}" fullword ascii
    $s14 = "return gRUYO;" fullword ascii
    $s15 = "if (zJcJi > 193957-527){return true;} else {return false;}" fullword ascii
    $s16 = "function lYwp(ngMmk) {" fullword ascii
    $s17 = "function coLpfFtO() {" fullword ascii
    $s18 = "return IKtJi.status;" fullword ascii
    $s19 = "function mBaQ(nNFPu) {" fullword ascii
    $s20 = "function nCIGwyezK() {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}