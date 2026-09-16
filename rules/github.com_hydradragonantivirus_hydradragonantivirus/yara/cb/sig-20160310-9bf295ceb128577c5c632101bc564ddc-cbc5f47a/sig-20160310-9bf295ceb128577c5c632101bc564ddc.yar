rule sig_20160310_9bf295ceb128577c5c632101bc564ddc {
  meta:
    description = "datamaliciousorder - file 20160310_9bf295ceb128577c5c632101bc564ddc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85155c5672493d230a86cadf06eb866e6ad6134be96eefeab838a1295873e5c9"

  strings:
    $s1  = "var ZFqpf = \"FjfBgV zsx pt.Shell ZtpLgZk Scri ArnI %TE MP% \\\\ aRSAWlbfy\".split(\" \");" fullword ascii
    $s2  = "var rR = true  , dCSu = Pkf[7] + Pkf[9] + Pkf[11];" fullword ascii
    $s3  = "return AAJwQVR[0] + AAJwQVR[2] + AAJwQVR[4] + \".F\" + AAJwQVR[7] + AAJwQVR[9] + AAJwQVR[12] + AAJwQVR[14];" fullword ascii
    $s4  = "var AAJwQVR = \"Sc COpiCiY r RjzKUxQdu ipting nyGLChv aQO ile waXdywfauJMLRl System HW VrKnC Obj GFIaVg ect uGbfzRc\".split(\" " ascii
    $s5  = "HAlpD.open(sAlSg,kNPBB,false);" fullword ascii
    $s6  = "var Pkf = (\"2.XMLHTTP daQOJfm UBEKI XML ream St bcxNiSeV AD SzFmSQR O EbGM D\").split(\" \");" fullword ascii
    $s7  = "function bRvP(ENaDH,yfxHf) {" fullword ascii
    $s8  = "return Rbd.size;" fullword ascii
    $s9  = "return lxCfwvA" fullword ascii
    $s10 = "function IXBhC(ZkeLYb) {" fullword ascii
    $s11 = "function uJJtV(gOgUeJ) {" fullword ascii
    $s12 = "function fMmMZuu(bHBj) {" fullword ascii
    $s13 = "return ixgXRTT(tR,ZFqpf[958-952]+ZFqpf[481-474]+ZFqpf[470-462]);" fullword ascii
    $s14 = "function JqPg(HAlpD,kNPBB,sAlSg) {" fullword ascii
    $s15 = "if (AHCGt == 899-699){return true;} else {return false;}" fullword ascii
    $s16 = "function laLAjvyU(Rbd) {" fullword ascii
    $s17 = "if (LTIGZ > 165571-265){return true;} else {return false;}" fullword ascii
    $s18 = "function QUrF(JApzD) {" fullword ascii
    $s19 = "function zgRXfWQWa(QUOwn,PtRSh,YRsKU,gjMg) {" fullword ascii
    $s20 = "function PgjG(LTIGZ) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}