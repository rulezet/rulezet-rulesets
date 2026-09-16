rule sig_20160321_0bb86252df8ffee677c6180770b12855 {
  meta:
    description = "datamaliciousorder - file 20160321_0bb86252df8ffee677c6180770b12855.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06840214dd26e29e9761ce0277ce7d20befe8297f39b5c2cd8fe6061887c93d9"

  strings:
    $s1  = "function mSOQF(kvp){return kvp;};function kjsXy(wg){return wg;};var N0 = \"1\\x362\";var JQYy = \"68\";var fE = \"\\x383\";var J" ascii
    $s2  = " (function oLy(){return wrDA;}()) + kxt(iOqh) + Dld(Bt) + mZ(UTIsn) + q0; bZ = n(); dEQAq = WScript[V + h + G(zlBcd) + u(jvIc)](" ascii
    $s3  = "rDHI() {return WScript[V + ZOle(h) + (function V0(){return zlBcd;}()) + JC(jvIc)](MuJ(JSL) + (function j(){return Kk;}()) + exAW" ascii
    $s4  = "W + (function WKzfn(){return abYvJ;}()) + z]();WScript[hu(xSKp) + AIed(lm) + (function lo(){return pZ;}())](gZTrr());var LJovG =" ascii
    $s5  = "s;}()) + WPf(W) + (function iRl(){return abYvJ;}()) + z]();WScript[XWzgM(xSKp) + lm + nPH(pZ)](gZTrr());var LJovG = new this[(fu" ascii
    $s6  = "urn Cln;}());};function BxVjw(ETFeO, VgdTe){return ETFeO - VgdTe;};function aqLed(){return V + (function oQf(){return h;}()) + (" ascii
    $s7  = "r (var x = 0; x < gZTrr() * 1; x++){if (DVkK() != 0){pome = true;tKcTp = true;break;}}function qgN() {return pome && tKcTp;};if " ascii
    $s8  = "+ mN + uICI + yY] < 4 ) {WScript[xSKp + Di(lm) + pZ](gZTrr() * 10)};QhII = false;} catch(e){};}DvkF = WScript[aqLed()](IzdzO + H" ascii
    $s9  = "Jds;}())]();Zcpp(vt);BIW = \"\" + (function k0(){return xXOf;}()) + AbS + PdP(ryiN) + K0 + Q0 + (function LT(){return r1;}()) + " ascii
    $s10 = "lLh(vljj) + aBT(e0) + dzM(Zvl));DvkF[(jNAs(fFJ) + z0(GD))]();DvkF[(function Yzeg(){return FocPR;}())] = 1;DvkF[dFBOl(qv) + (func" ascii
    $s11 = "function eb(){return zlBcd;}()) + jvIc;};function gZTrr(){return 22;};function DVkK(){var LJovG = new this[(function cju(){retur" ascii
    $s12 = "(eFW)] = 0;DvkF[UfAgh + (function IJ(){return AjvKv;}()) + dOgN(l) + LV(ZJnZ) + Cn(qMsRQ)](vt, 2 );DvkF[(function sYJ(){return V" ascii
    $s13 = "X + (function HMH(){return XJ;}()) + sz);}();function Zcpp(Wp){FHXUH[(function IPqGx(){return CMwun;}())](Wp, 0, 0);};function n" ascii
    $s14 = "n IJH;}()) + (function DhS(){return varIT;}())]();var m0 = LJovG[(function sgZP(){return zfPhX;}()) + B + (function Y(){return X" ascii
    $s15 = "(Zph) + iykvv(Z) + hJCl + (function mf(){return Ux;}()) + Ky + pome ? Px(iQTHQ) + tA : mSOQF(JLD) + (function PUL(){return fE;}(" ascii
    $s16 = "tion Yc(){return kTtrC;}()) + s1(s0)](dEQAq[VH(zkzY) + (function TdK(){return KxR;}()) + uk + T]);DvkF[LMMiz + zrTFn(S0) + qIwbg" ascii
    $s17 = " new this[ysgWE(IJH) + varIT]();var m = LJovG[p(zfPhX) + hqjm(B) + Xs + vHrgp(W) + AXXp(abYvJ) + (function vRez(){return z;}())]" ascii
    $s18 = "(K) + (function bxobq(){return nnk;}()) + iVJ + nd(qvp), false);dEQAq[(function Bw(){return JmAb;}())]();while (dEQAq[TS(GeYRn) " ascii
    $s19 = "eturn VP;}()) + Ihk(fnmy) + (function MdpIP(){return CS;}()) + (function ePHf(){return AjL;}()) + (function sUld(){return S;}())" ascii
    $s20 = "(qgN()){vt = FHXUH[bi(fH) + (function rRvhT(){return OErQj;}()) + (function Gdv(){return r;}()) + Wjvm(rQCRi) + (function xh(){r" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}