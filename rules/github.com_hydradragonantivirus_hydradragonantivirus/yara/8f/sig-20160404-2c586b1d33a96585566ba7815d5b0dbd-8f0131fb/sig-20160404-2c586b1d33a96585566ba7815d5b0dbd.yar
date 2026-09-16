rule sig_20160404_2c586b1d33a96585566ba7815d5b0dbd {
  meta:
    description = "datamaliciousorder - file 20160404_2c586b1d33a96585566ba7815d5b0dbd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5db411814c584af2e5b91af6944a3f255cbbbc93cc573675297af6464d370c06"

  strings:
    $s1  = "var kP = true  , CHmE = STi[7] + STi[9] + STi[11];" fullword ascii
    $s2  = "return HYtsyOe[0] + HYtsyOe[2] + HYtsyOe[4] + \".F\" + HYtsyOe[7] + HYtsyOe[9] + HYtsyOe[12] + HYtsyOe[14];" fullword ascii
    $s3  = "var STi = (\"2.XMLHTTP mESVwDn MEYdu XML ream St YQtHQrVm AD jQrBakR O vBmp D\").split(\" \");" fullword ascii
    $s4  = "var HYtsyOe = xwYKz(GPWYOikfjz+\" \"+\"System Go qnAHg Obj aWlkTV ect HABFyAm yaODT\", \" \");" fullword ascii
    $s5  = "vceh.open(csqYc,TWJFd,false);" fullword ascii
    $s6  = "if (T >= XRyvA.length) {break;}" fullword ascii
    $s7  = "function rFeW(teuHp,TWJFd,csqYc) {" fullword ascii
    $s8  = "function hQNuz(CYBOEXxX,KAXB) {" fullword ascii
    $s9  = "function AeMpMTa(vUOy) {" fullword ascii
    $s10 = "return sMEXW.status;" fullword ascii
    $s11 = "function fSOY(FolVH) {" fullword ascii
    $s12 = "return \"LqcrHJMdbVUAOB\";" fullword ascii
    $s13 = "function LECLr(GuJjaG) {" fullword ascii
    $s14 = "function diDfeyUF(FqnQ) {" fullword ascii
    $s15 = "function VzHo(hxWEN,WsFYb) {" fullword ascii
    $s16 = "Heh = e; break; " fullword ascii
    $s17 = "function SHRATb(ZGYf,TvTbZY) {" fullword ascii
    $s18 = "function fiEdyZT(BbLe,ZMfHq) {" fullword ascii
    $s19 = "function ChvWoD(mvjgZrG) {" fullword ascii
    $s20 = "if (wgZib > 155346-873){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}