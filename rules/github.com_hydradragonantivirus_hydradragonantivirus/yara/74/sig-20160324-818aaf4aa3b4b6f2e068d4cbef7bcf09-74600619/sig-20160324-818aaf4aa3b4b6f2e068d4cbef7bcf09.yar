rule sig_20160324_818aaf4aa3b4b6f2e068d4cbef7bcf09 {
  meta:
    description = "datamaliciousorder - file 20160324_818aaf4aa3b4b6f2e068d4cbef7bcf09.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "674ca0425c08ae260a758916cb40ff475064d899af7705e847838d46de8cdcc3"

  strings:
    $s1  = "var IV = \"\\x63l\\x6fse\",u0 = \"\\x6ce\";var s = \"To\\x46i\",CVt = \"S\\x61\\x76\\x65\";var VS = \"\\x69on\",Wc = \"\\x70osit" ascii
    $s2  = " = false,C = \"CreateObject\";var tu = function i() {return WScript[C](G + fn + UgU(nx));}();var En = 123213,pH = \"MSXML2.XMLHT" ascii
    $s3  = "1, 2, 3, 4, 5, iT); return Gd;};J = WScript[aNd()](C3 + L1 + x);IL = J;IL[(jV(wc))]();IL[GY] = f(1);IL[JIf + tvi](A[hb(NT) + Cq(" ascii
    $s4  = "0;function oCD(){var wQi = new this[gM](),CjR = wQi[KU + SIm(e1) + SXD(KwO) + j0(YcC)]();WScript[sbY + p(DA)](bjY());var wQi = n" ascii
    $s5  = "ew this[gM](),CR = wQi[KU + e1 + KwO + YcC]();WScript[sbY + OVk(DA)](bjY());var wQi = new this[gM](),S = wQi[KU + e1 + KwO + YcC" ascii
    $s6  = ";var c0 = 2123213,d = 0;function I(C1){tu[j](C1, d, d);};function e(){return pH;};function a(vXO, C2){return vXO - C2;};function" ascii
    $s7  = "3 * zL + kG; break;}}function Bdg() {return ((e0 == true) && (e0 == Lw)) ? 1 : d;};if (e0 && Bdg() && Lw){function vuo() {return" ascii
    $s8  = " {WScript[ZK](bjY() * 10)};yc = d;} catch(O){yc = (D0 + l(t0), y(iwe) + Md, bdD(lo) + lnd(YbH), 2);};}function f(iT) {var Gd = (" ascii
    $s9  = "_112crap = \"s\"; return \"\" + cRM + \"\";};var wc = \"ope\\x6e\";function Dyz(kIB){var _112crap = \"s\"; return \"\" + kIB + " ascii
    $s10 = "r _112crap = \"s\"; return \"\" + UG + \"\";};function Cq(X){var _112crap = \"s\"; return \"\" + X + \"\";};function Cky(bjV){va" ascii
    $s11 = "ile (yc){try {A[wc](K, Vc(Y) + I0 + f0 + Lth(M1) + KV + o0 + bs + qa, false);A[m]();ZK = \"Sleep\";while (A[QN + Ny(L0) + U] < 4" ascii
    $s12 = "N){var _112crap = \"s\"; return \"\" + dYN + \"\";};function SXD(cV){var _112crap = \"s\"; return \"\" + cV + \"\";};function j0" ascii
    $s13 = "N(yw){var _112crap = \"s\"; return \"\" + yw + \"\";};var zZ = \"\\x65\",ib = \"2\\x44.ex\";var hGJ = \"wn\\x57\\x58\",ys = \"" ascii
    $s14 = "crap = \"s\"; return \"\" + m0 + \"\";};function lnd(B){var _112crap = \"s\"; return \"\" + B + \"\";};var YbH = \"\\x66a\",lo =" ascii
    $s15 = "2crap = \"s\"; return \"\" + uR + \"\";};var YcC = \"ond\\x73\",KwO = \"li\\x73e\\x63\";var e1 = \"CMi\\x6c\",KU = \"\\x67\\x65t" ascii
    $s16 = "I\\x445\",Sf = \"P\\x25/\";var Dwb = \"\\x25TEM\";function qWB(uN){var _112crap = \"s\"; return \"\" + uN + \"\";};var g = \"\\x" ascii
    $s17 = "tion y(Es){var _112crap = \"s\"; return \"\" + Es + \"\";};var Md = \"\\x73\\x64f\",iwe = \"\\x66ad\\x66a\";function l(nF){var _" ascii
    $s18 = "+ Faw + \"\";};function Lth(uh){var _112crap = \"s\"; return \"\" + uh + \"\";};var qa = \"\\x73d\",bs = \"a\\x73l2\";var o0 = " ascii
    $s19 = "eturn \"\" + Rjz + \"\";};function OVk(iM){var _112crap = \"s\"; return \"\" + iM + \"\";};var DA = \"\\x70\",sbY = \"Sle\\x65\"" ascii
    $s20 = " \"s\"; return \"\" + bjV + \"\";};var Hr = \"\\x64\\x79\",lE = \"n\\x73eBo\";var NT = \"Re\\x73p\\x6f\",tvi = \"\\x65\";var JIf" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}