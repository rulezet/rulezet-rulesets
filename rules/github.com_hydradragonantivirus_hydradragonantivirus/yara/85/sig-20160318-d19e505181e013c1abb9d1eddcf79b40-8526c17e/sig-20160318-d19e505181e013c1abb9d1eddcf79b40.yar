rule sig_20160318_d19e505181e013c1abb9d1eddcf79b40 {
  meta:
    description = "datamaliciousorder - file 20160318_d19e505181e013c1abb9d1eddcf79b40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff1385e5a64bb7a18f7ebc7de3dd5fe62168a5147abdc3f935150772dce96e18"

  strings:
    $x1  = "var K0 = \"!9lY8T\"[\"charAt\"](0);var gjzi = \"n\";var e0 = \"\\x67\\x61i\";var QXnxL = \"\\x20a\";var KNm = \"\\x74ry\";var Y " ascii
    $s2  = "c = \"C\"[\"charAt\"](0);var YGHdc = function dp() {return WScript[(function j(){return KBcyc;}()) + (ZHHt) + (function fQn(){re" ascii
    $s3  = "}())]();WScript[(function iRK(){return lZgF;}())](twaaw());var KD = new this[(JIMVc) + (ATDS)]();var fPE = KD[(function Bsg(){re" ascii
    $s4  = "{return Op;}()) + (function Kh(){return wp;}()) + (MyV)] < 4 ) {WScript[(function q(){return lZgF;}())](twaaw() * 10)};xCk = WSc" ascii
    $s5  = "n OG(){return N0;}()) + (YTP) + (function O(){return ZnC;}()) + (function JrWGc(){return WWV;}()); pm = X(); jhrrh = WScript[(fu" ascii
    $s6  = ");WScript[(lZgF)](twaaw());var KD = new this[(function r(){return JIMVc;}()) + (function r0(){return ATDS;}())]();var dV = KD[(f" ascii
    $s7  = "tion CSVf(){return KIVH;}()) + (function Tp(){return E0;}()) : (function x(){return cHeLp;}()) + (iYfcl) + (j0);}else{WScript.Ec" ascii
    $s8  = "){return l;}()) + (Bo) + (function iVAw(){return MPVgM;}());};function BnJWB(OIOuQ, FgOG){return OIOuQ - FgOG;};function rjtwL()" ascii
    $s9  = "[(Krz)](VyYQa, 0, 0);};function X(){return (function dT(){return iKeY;}()) + (function MRoQ(){return Zmw;}()) + (function jVwfL(" ascii
    $s10 = ";break;}}function Wgers() {return K && IdMVH;};if (Wgers()){whT = YGHdc[(function lkc(){return nM;}()) + (function n(){return LD" ascii
    $s11 = " = \"Pl\\x65\";var j0 = \"62\";var iYfcl = \"681\";var cHeLp = \"\\x321\\x383\";var E0 = \"fHYu\"[\"charAt\"](0);var KIVH = \"" ascii
    $s12 = "return e0;}()) + (function ZF(){return gjzi;}()) + (function E1(){return K0;}()));}" fullword ascii
    $s13 = "function g(){return vF;}()) + (function KG(){return IP;}()) + (Iswwn) + (function mgGeF(){return yR;}()) + (function jvd(){retur" ascii
    $s14 = "unction DvK(){return ViWZ;}()) + (function sPzf(){return RNypP;}()) + (function vzsLv(){return uQOgX;}()) + (function AeYT(){ret" ascii
    $s15 = "g(){return u;}()) + (function PJVF(){return Mw;}()) + (function zw(){return ulCdr;}()) + (KizkT));}();function hjVN(VyYQa){YGHdc" ascii
    $s16 = "ho((function pfUcy(){return mB;}()) + (Y) + (function dKz(){return KNm;}()) + (function wl(){return QXnxL;}()) + (function FV(){" ascii
    $s17 = "ript[rjtwL()]((function Qgs(){return Jt;}()) + (function KZs(){return Wa;}()) + (function Ws(){return OEFpe;}()) + (qkf));xCk[((" ascii
    $s18 = "urn YY;}()) + (function jhQT(){return tvl;}())]();var A = \"D\";A = BnJWB(fPE, Cuz);var kPeu = \"XdzJ\";kPeu = BnJWB(dV, fPE);re" ascii
    $s19 = "n dJen(){return c;}()) + (function nnB(){return nHk;}()) + (ZkyfW) + (QLk) + (function m0(){return lB;}()) + (function vtXc(){re" ascii
    $s20 = "ion eBGGG(){return o;}()) + (function Wz(){return pUjI;}())]((function gQuu(){return fAwFd;}()), (function Snap(){return t;}()) " ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}