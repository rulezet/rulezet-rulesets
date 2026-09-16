rule sig_20160303_b50c28c9bc2d03dab8966dad425cd11b {
  meta:
    description = "datamaliciousorder - file 20160303_b50c28c9bc2d03dab8966dad425cd11b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7545cf14eeb7af48fe5b66dece0242236b26541ccc5642f49e98a087fcec2183"

  strings:
    $s1  = "var cu = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(RLkCW);" fullword ascii
    $s3  = "var xOv = (flI + \"TTP\" + \" MvSwykA kxTun XML ream St EJRtwTrl AD fgYHDGy OD\").split(\" \");" fullword ascii
    $s4  = "var jO = true  , EBQk = xOv[7] + \"\" + xOv[9];" fullword ascii
    $s5  = "return \"Sc\" + \"r\" + nPbFtex + \".F\" + peNgaWIFRY + AuYCp + \"Obj\" + \"ect\";" fullword ascii
    $s6  = "KXXGL.open(Xuwce,CKHef,false);" fullword ascii
    $s7  = "function Nntz(KXXGL,CKHef,Xuwce) {" fullword ascii
    $s8  = "function Zngy(wjoSq) {" fullword ascii
    $s9  = "BLd = h; break; " fullword ascii
    $s10 = "if(h>=E.length) {break;}" fullword ascii
    $s11 = "return FGsCP.status;" fullword ascii
    $s12 = "function cXHQvXSZx(EtBPy,JeorY,OrMKP) {" fullword ascii
    $s13 = "function DZKBTVTF() {" fullword ascii
    $s14 = "function yQVL(edUvv) {" fullword ascii
    $s15 = "return new ActiveXObject(EZcPUN);" fullword ascii
    $s16 = "function zwyO(ZzGMj,Zlhjc) {" fullword ascii
    $s17 = "if (aixcf == 787-587){return true;} else {return false;}" fullword ascii
    $s18 = "function qPPH(FGsCP) {" fullword ascii
    $s19 = "function ySVb(RLkCW) {" fullword ascii
    $s20 = "if (IcgaT > 156847-776){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}