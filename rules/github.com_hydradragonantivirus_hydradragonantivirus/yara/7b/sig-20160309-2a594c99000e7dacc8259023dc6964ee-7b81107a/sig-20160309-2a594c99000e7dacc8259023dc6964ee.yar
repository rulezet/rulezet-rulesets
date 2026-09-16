rule sig_20160309_2a594c99000e7dacc8259023dc6964ee {
  meta:
    description = "datamaliciousorder - file 20160309_2a594c99000e7dacc8259023dc6964ee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd1e5635927d56d0643703660306f5803a2b3a0d032b12dd8aa3f294547e6f34"

  strings:
    $s1  = "var JV = true  , LJFX = hqW[7] + hqW[9] + hqW[11];" fullword ascii
    $s2  = "var hqW = (\"2.XMLHTTP NQJzXVC hgfeX XML ream St bkEABGcM AD jCSVUyq O jKFL D\").split(\" \");" fullword ascii
    $s3  = "tpXRQ.open(WxsGv,NtwpH,false);" fullword ascii
    $s4  = "function wrTsrBOwC(EPgeGsCTuaf) {" fullword ascii
    $s5  = "function ZuLOfYi(Qfjv) {" fullword ascii
    $s6  = "return ijAfjaL(Lg,xrBGu[241-235]+xrBGu[687-680]+xrBGu[859-851]);" fullword ascii
    $s7  = "if(c>=p.length) {break;}" fullword ascii
    $s8  = "if (WHxGw > 174835-957){return true;} else {return false;}" fullword ascii
    $s9  = "function jtGIXrHX(aFVdP,tFGucq) {" fullword ascii
    $s10 = "if (bMwih == 1107-907){return true;} else {return false;}" fullword ascii
    $s11 = "if (W >= kysqZ.length) {break;}" fullword ascii
    $s12 = "return wcAXvjY[0] + wcAXvjY[2] + wcAXvjY[4] + \".F\" + wcAXvjY[7] + wcAXvjY[9] + wcAXvjY[12] + wcAXvjY[14];" fullword ascii
    $s13 = "function UmIj(hzPuQ) {" fullword ascii
    $s14 = "return REknj;" fullword ascii
    $s15 = "function xhGI(RMzfD,inoKt) {" fullword ascii
    $s16 = "return dTehGnC" fullword ascii
    $s17 = "function YtmRJqAzN(gyNtn,BORUA,JoXUw,nCHf) {" fullword ascii
    $s18 = "return new ActiveXObject(hokGcl);" fullword ascii
    $s19 = "return Qfjv.responseBody;" fullword ascii
    $s20 = "function ijAfjaL(Ywar,Vtkoz) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}