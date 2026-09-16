rule sig_20160323_984dee6989d4ef07c5e6e046186575fe {
  meta:
    description = "datamaliciousorder - file 20160323_984dee6989d4ef07c5e6e046186575fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64be656888af586f0869b704622cd5ff1191fcd952a550757215a2d67d860311"

  strings:
    $s1  = "function y1(o1){var _112crap = \"s\"; return \"\" + o1 + \"\";};function bK(ysY){var _112crap = \"s\"; return \"\" + ysY + \"\";" ascii
    $s2  = ".com\";var E0 = \"ara\",u = \"/fi\\x68a\";var PA = tI[\"char\"+\"\\x41\"+\"\"+\"\\x74\"+\"\"](2),F1 = \"\\x68ttp:\";function SiQ" ascii
    $s3  = "FU = false;var H = function a() {return WScript[ZQ0(s) + qpl(tjx) + kj(E) + n + oNU](L(Eo) + SE(D) + kCh(Zyh));}();function nKJ(" ascii
    $s4  = "xM) + ntw(s0) + CV(k1) + o0(vht)]();WScript[fOj + p0(c0)](SMp());var v = new this[B0(BUM) + T0(i)](),amn = v[Erc(IuX) + vYC(Jw) " ascii
    $s5  = "M) + s0 + eZ(k1) + db(vht)]();WScript[HdC(fOj) + c0](SMp());var v = new this[cH(BUM) + Ne(i)](),eN = v[IuX + aB(Jw) + k0 + oCn(a" ascii
    $s6  = "s\"; return \"\" + bR + \"\";};var W1 = \"GET\";function PL(HT){var _112crap = \"s\"; return \"\" + HT + \"\";};var sE = \"op\\x" ascii
    $s7  = "IW){H[l(T)](IW, 0, 0);};function bo(){return XPs + FZx(bAp) + YmP(Seg) + GIz + Jt(fco) + Fp(x);};function QU(J, LZ){return J - L" ascii
    $s8  = "};if (yJ && OC() && rb){function Me() {return H[GpT(XY) + Pu(eN0) + dl + i0 + T1(Y) + jqh(U) + aC(gH) + yvI(YW)](m + Jk(nyt)) + " ascii
    $s9  = "; rb = true; I = \"07t9gasdf76ags\" + 123313 * YGd + I; break;}}function OC() {return ((yJ == rb) && (yJ == true)) ? true : fals" ascii
    $s10 = "T = \"Run\";function L(g){var _112crap = \"s\"; return \"\" + g + \"\";};function SE(EgI){var _112crap = \"s\"; return \"\" + Eg" ascii
    $s11 = "s)]();while (p[htu(t1) + oFL + t2(EH)] < 4 ) {WScript[CT(fOj) + ylc(c0)](SMp() * 10)};bLL = false;} catch(mND){bLL = (p1 + Rob(p" ascii
    $s12 = " + \"\";};function Ih(iud){var _112crap = \"s\"; return \"\" + iud + \"\";};function c(iSJ){var _112crap = \"s\"; return \"\" + " ascii
    $s13 = "AVJ + \"\";};var c0 = \"p\",fOj = \"Slee\";function Ge(jlH){var _112crap = \"s\"; return \"\" + jlH + \"\";};function g1(eEv){va" ascii
    $s14 = " \"fa\\x64\";function Rob(u0){var _112crap = \"s\"; return \"\" + u0 + \"\";};function mg(EW){var _112crap = \"s\"; return \"\" " ascii
    $s15 = "+ \"\";};function MuN(b0){var _112crap = \"s\"; return \"\" + b0 + \"\";};var Q = \"EhNdVtAdk\",u1 = \"\\x69on\";var C0 = Q[\"ch" ascii
    $s16 = " \"s\"; return \"\" + eEv + \"\";};function svo(Tvt){var _112crap = \"s\"; return \"\" + Tvt + \"\";};function v0(PBu){var _112c" ascii
    $s17 = "; return \"\" + wpO + \"\";};function zJO(Cv){var _112crap = \"s\"; return \"\" + Cv + \"\";};var qAI = \"W5o\",X = \"\\x64y\";v" ascii
    $s18 = "= \"LH\";var GIz = \"M\",Seg = \"\\x32.X\";var bAp = \"X\\x4dL\",XPs = \"\\x4dS\";function l(y){var _112crap = \"s\"; return \"" ascii
    $s19 = "function SMp(){return 22;};var YGd = 0,I = 0;function mM(){var v = new this[BUM + i](),gK = v[Ge(IuX) + g1(Jw) + svo(k0) + v0(ax" ascii
    $s20 = "= \"s\"; return \"\" + Knc + \"\";};function NF(s2){var _112crap = \"s\"; return \"\" + s2 + \"\";};var e1 = \"f\",N2 = \"\\x66a" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}