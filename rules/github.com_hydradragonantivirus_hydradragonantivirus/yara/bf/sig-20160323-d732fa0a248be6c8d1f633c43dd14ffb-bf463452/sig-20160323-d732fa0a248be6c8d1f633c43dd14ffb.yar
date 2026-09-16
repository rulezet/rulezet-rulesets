rule sig_20160323_d732fa0a248be6c8d1f633c43dd14ffb {
  meta:
    description = "datamaliciousorder - file 20160323_d732fa0a248be6c8d1f633c43dd14ffb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3de070e8b149918748b9dc358cc92ed545afc67fb8b4faeabe5eed89ddf113ad"

  strings:
    $s1  = "function L0(Wb){var _112crap = \"s\"; return \"\" + Wb + \"\";};function MDH(m1){var _112crap = \"s\"; return \"\" + m1 + \"\";}" ascii
    $s2  = "var g = uG[\"\"+\"\\x63\"+\"h\"+\"\\x61\"+\"rAt\"](3),Cs = \"ateOb\";var fn = \"\\x43\\x72e\",vx = false;var Vud = function M() " ascii
    $s3  = "his[EJ(Nrt)](),CCO = HIo[NP(kr) + N(vc) + Xu(NZ) + k(x) + qTL(V)]();WScript[yGN + zy(FmT)](c());var HIo = new this[c0(Nrt)](),ON" ascii
    $s4  = "+ bkO, true);};}function Q(vm) {var m = (1, 2, 3, 4, 5, vm); return m;};eK = (E) ? 14134 : 414234;uz = WScript[Ey()](Kr(cEk) + F" ascii
    $s5  = "o = HIo[qRs(kr) + xc(vc) + t0(NZ) + x + kJo(V)]();WScript[ECH(yGN) + FmT](c());var HIo = new this[Q0(Nrt)](),w0 = HIo[ti(kr) + Y" ascii
    $s6  = " bWm(kD) + n1(i) + TD(y0);}; O = CB(); vW = WScript[fn + Cs + Bzp(g) + xS](O); var MH = true; while (MH){try {vW[QmV(yT)](uv(TWk" ascii
    $s7  = "DgAeeXp\",Sn = qrk[\"\"+\"\\x63\"+\"h\"+\"\\x61\"+\"rAt\"](3);var xn0 = \"cl\\x6fs\";function Xl(B){var _112crap = \"s\"; return" ascii
    $s8  = "+ Yiw + \"\";};var TWk = \"GET\";function QmV(lNp){var _112crap = \"s\"; return \"\" + lNp + \"\";};function Q2(Bew){var _112cra" ascii
    $s9  = "return fg + Ft + xn(E0) + ssj(vt);};function ckU(a, jnx){return a - jnx;};function Ey(){return fn + Cs + r(g) + P(xS);};/*@cc_on" ascii
    $s10 = "Eq = \"07t9gasdf76ags\" + 123313 * eK + Eq; break;}}function Ns() {return ((E == VpW) && (E == true)) ? true : false;};if (E && " ascii
    $s11 = "() && VpW){function w() {return Vud[w3(H) + VU(T) + M0 + K(AXW) + J(w2) + A0(hWU) + DPx(Imt) + Mr](ATc(fDE) + n0(u1)) + zn(q0) +" ascii
    $s12 = "X\\x4dL\";function Bef(VYy){var _112crap = \"s\"; return \"\" + VYy + \"\";};var atq = \"Run\";function Mz(Bla){var _112crap = " ascii
    $s13 = "ZeG(a3) + QOJ(D) + os(v0)] < 4 ) {WScript[G(yGN) + FmT](c() * 10)};MH = false;} catch(pcl){MH = (DQS(S), wF(Mpd) + GOm, oI(vFx) " ascii
    $s14 = "r x = \"\\x6cisec\",NZ = \"\\x54CMi\\x6c\";var vc = \"et\\x55\",kr = y[\"\"+\"\\x63\"+\"h\"+\"\\x61\"+\"rAt\"](0);function EJ(Ef" ascii
    $s15 = "function L0(Wb){var _112crap = \"s\"; return \"\" + Wb + \"\";};function MDH(m1){var _112crap = \"s\"; return \"\" + m1 + \"\";}" ascii
    $s16 = "), rFf(AXt) + tM(dn) + lg(Tkg) + aS(eTc) + pbb + Xmx(s) + zy0 + bJ(mXf) + vJm(We), false);vW[nQ(r0) + u2]();while (vW[wz(otW) + " ascii
    $s17 = "turn \"\" + L + \"\";};function k(u0){var _112crap = \"s\"; return \"\" + u0 + \"\";};function qTL(TBW){var _112crap = \"s\"; re" ascii
    $s18 = "n \"\" + G0 + \"\";};var GOm = \"asdf\",Mpd = \"fadf\";function DQS(xRw){var _112crap = \"s\"; return \"\" + xRw + \"\";};var S " ascii
    $s19 = "return \"\" + mG + \"\";};function bWm(fF){var _112crap = \"s\"; return \"\" + fF + \"\";};function n1(W){var _112crap = \"s\"; " ascii
    $s20 = "C){var _112crap = \"s\"; return \"\" + eC + \"\";};var njy = \"\\x6ce\",H0 = \"i\";var sai = \"\\x6fF\",osS = \"ve\\x54\";var T0" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}