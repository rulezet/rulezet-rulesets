rule sig_20160321_7e02da8f585a7840bfb5d66bcbe9e590 {
  meta:
    description = "datamaliciousorder - file 20160321_7e02da8f585a7840bfb5d66bcbe9e590.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b3583dd131f6bc101d0da6ec00ab95e52dd2c2d6cfdcdfd96e7d0d83ab908b9"

  strings:
    $x1  = "function iT(Qh){return Qh;};var hJ = \"shR3\";var haoge = \"\\x36\\x38162\";var GMDOl = hJ[\"charA\\x74\"](3);var UyFOx = \"\\x3" ascii
    $s2  = ")](JI() * 10)};IvlJB = false;} catch(e){};}T = WScript[NzTfQ()](qJ(uLW) + dcsk + RlmQ + DGet(YBZq) + h0(qLT) + (function nAWSs()" ascii
    $s3  = "{return XpV;}()) + bwykh + PGjUz(N0) + BA + whMQl(u1) + kMaaB; Iw = NJToF(); IcpGc = WScript[KOr + (function SkQYx(){return t;}(" ascii
    $s4  = ");var CEi = ZT[e + (function ei(){return jqP;}()) + (function Q(){return aJw;}()) + jZnIB(F) + qc(MDPV) + UWBi]();WScript[QJIE +" ascii
    $s5  = "(function fprWF(){return jqP;}()) + aJw + F + inIX(MDPV) + xqfo(UWBi)]();WScript[RWoe(QJIE) + vr(yjG)](JI());var ZT = new this[e" ascii
    $s6  = "() {return WScript[(function zFDzW(){return KOr;}()) + t + (function wb(){return TzM;}()) + zOG]((function sv(){return k;}()) + " ascii
    $s7  = "tion qo(){return c0;}()) + (function Yv(){return mhaVw;}()) + FdnoR + bv] < 4 ) {WScript[QJIE + (function VGfIN(){return yjG;}()" ascii
    $s8  = ";var gNT = \"m\";var znmh = \"orth.\";var x = \"npapw\";var csmV = \"w\\x77.b\\x65\";var bqp = \"/\\x2fw\";var Uf = \"http:\";fu" ascii
    $s9  = "Ezno(){return T1;}()) + O(qbK);};function RO(New, Y){return New - Y;};function NzTfQ(){return PR(KOr) + t + (function xAs(){retu" ascii
    $s10 = "return WTwVP;};function whMQl(jMWjG){return jMWjG;};var ZBfDV = \"La9t5EF4\";var CEzdy = \"RfRvF1\";var kMaaB = \"\\x67.exe\";va" ascii
    $s11 = "var SUd = 0; SUd < JI() * 1; SUd++){if (N() != 0){UeQcj = true;sMTb = true;break;}}function fz() {return UeQcj && sMTb;};if (fz(" ascii
    $s12 = "](1);var ZiH = \"\\x6f\\x70e\";function qJ(oAeYf){return oAeYf;};function DGet(smg){return smg;};function h0(A0){return A0;};var" ascii
    $s13 = "(function u(){return ODVEs;}()) + (function Rz(){return A;}()) + (function YTVAW(){return yk;}()));}();function mP(qf){xNYsi[RwN" ascii
    $s14 = "Gc[(function tZge(){return JAAhU;}()) + (function huJi(){return syUe;}()) + (function HZh(){return ri;}())]();while (IcpGc[(func" ascii
    $s15 = "rn NY;}()) + kG(eAwWB)] = 0;T[(function Dd(){return XGoB;}()) + pLOr(dffw) + (function QDogB(){return AYIt;}())](T0, 2 );T[PwPtu" ascii
    $s16 = "l0(bqp) + f(csmV) + Nh(x) + znmh + gNT + (function Ku(){return nQgUe;}()) + Ewx(rKK) + (function Qw(){return p0;}()), false);Icp" ascii
    $s17 = "sD(OVm) + b(dWO)](qf, 0, 0);};function NJToF(){return jjtmb(qijp) + KYrC(Oa) + (function BzP(){return TP;}()) + jpO + (function " ascii
    $s18 = "zE + vqCxO(DDzFY)]();var pfC = ZT[e + Ryn(jqP) + iDm(aJw) + HZLW(F) + (function pA(){return MDPV;}()) + UWBi]();var BQWn = \"uBz" ascii
    $s19 = "return f0;}()) + BPis(PqiLG) + Hb + SjzWH(GKiTl) + G0(QaML) + M + GW + (function iJt(){return IBD;}()) + UeQcj ? uOqbl(gO) + (fu" ascii
    $s20 = " SysBb(yjG)](JI());var ZT = new this[ezE + (function u0(){return DDzFY;}())]();var QSaCp = ZT[(function xWusb(){return e;}()) + " ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}