rule sig_20160322_cd604920f1c802b280c0a4724835c4d1 {
  meta:
    description = "datamaliciousorder - file 20160322_cd604920f1c802b280c0a4724835c4d1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "83faf65cbab03c671683efb2796922935f97f6ea384ea9be17b18138494b3629"

  strings:
    $s1  = "return WScript.CreateObject(qNbGF);" fullword ascii
    $s2  = "return NcCI.ExpandEnvironmentStrings(XrFtp);" fullword ascii
    $s3  = "function iXovGJs(NcCI,XrFtp) {" fullword ascii
    $s4  = "return kYEKyww[0] + kYEKyww[2] + kYEKyww[4] + \".F\" + kYEKyww[7] + kYEKyww[9] + kYEKyww[12] + kYEKyww[14];" fullword ascii
    $s5  = "var XI = true  , Evkh = Gdb[7] + Gdb[9] + Gdb[11];" fullword ascii
    $s6  = "dOYI.open(vfaOV,ukqZF,false);" fullword ascii
    $s7  = "var Gdb = (\"2.XMLHTTP jMsJmhK PcPtA XML ream St TRBkOgGJ AD aBpYqwp O vzbB D\").split(\" \");" fullword ascii
    $s8  = "var kYEKyww = xTKEC(kNKahGIxmy+\" \"+\"System IK BriVv Obj ZNEmKa ect FLAYabL LjHFR\", \" \");" fullword ascii
    $s9  = "if (hUchr > 198615-446){return true;} else {return false;}" fullword ascii
    $s10 = "return new ActiveXObject(pOgfum);" fullword ascii
    $s11 = "if (LZTOb == 772-572){return true;} else {return false;}" fullword ascii
    $s12 = "function BwpF(SzXya) {" fullword ascii
    $s13 = "return luhjkc.position=653-653;" fullword ascii
    $s14 = "function DLJrEVgrq(lqZEa) {" fullword ascii
    $s15 = "function qrzys(luhjkc) {" fullword ascii
    $s16 = "function UhPmu(pOgfum) {" fullword ascii
    $s17 = "return fezwX;" fullword ascii
    $s18 = "function GMzhiBF(rsXP) {" fullword ascii
    $s19 = "LdU = w; break; " fullword ascii
    $s20 = "if (i >= SzXya.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}