rule sig_20160411_97b5f693aec0eaddea926bf3c6f3d2ed {
  meta:
    description = "datamaliciousorder - file 20160411_97b5f693aec0eaddea926bf3c6f3d2ed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9561760629ecd485d9fbc884e6acde307f37cc0187a43280c68e485b444c3b20"

  strings:
    $s1  = "return yEAbFNq[0] + yEAbFNq[2] + yEAbFNq[4] + \".F\" + yEAbFNq[7] + yEAbFNq[9] + yEAbFNq[12] + yEAbFNq[14];" fullword ascii
    $s2  = "var tU = true  , mRDc = Pkm[7] + Pkm[9] + Pkm[11];" fullword ascii
    $s3  = "var Pkm = (\"2.XMLHTTP YltOTGQ GugAX XML ream St yVtTzmXB AD FEvOfJr O AvJy D\").split(\" \");" fullword ascii
    $s4  = "mGMd.open(RiUsw,mHYlc,false);" fullword ascii
    $s5  = "eval(function(p,a,c,k,e,d){e=function(c){return c};if(!\"\".replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d" ascii
    $s6  = "return bbbvAX[yJsZ[649-649]]=768-768;" fullword ascii
    $s7  = "function fzGn(Juawv) {" fullword ascii
    $s8  = "function yvlIIl(YKbMztB) {" fullword ascii
    $s9  = "return ZtYh[xpcpoJx[0]+xpcpoJx[1]];" fullword ascii
    $s10 = "return sZYTp.status;" fullword ascii
    $s11 = "if(X>=y.length) {break;}" fullword ascii
    $s12 = "return fhLQQrx[0];" fullword ascii
    $s13 = "if (k >= edDgS.length) {break;}" fullword ascii
    $s14 = "function QPtBonS(ZtYh) {" fullword ascii
    $s15 = "return bHo[CvJT[0]](rBGxS);" fullword ascii
    $s16 = "return ukAUUKN(AX,ljFsLe+IYHpo[239-231]);" fullword ascii
    $s17 = "return new ActiveXObject(JHbH);" fullword ascii
    $s18 = "return hahkm;" fullword ascii
    $s19 = "function USJk(eoMTy) {" fullword ascii
    $s20 = "function IigUN(ZyhotbtI,pKcL) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}