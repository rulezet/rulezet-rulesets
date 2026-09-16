rule sig_20160323_d535987aa536a66a6e2f69ce3ea80434 {
  meta:
    description = "datamaliciousorder - file 20160323_d535987aa536a66a6e2f69ce3ea80434.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80f59313ec0e0da6471b2f5c3d848fe0c14e4af085e92f6306d43bbe03a8ea6a"

  strings:
    $s1  = "function mbr(U1){var _112crap = \"s\"; return \"\" + U1 + \"\";};function r2(z0){var _112crap = \"s\"; return \"\" + z0 + \"\";}" ascii
    $s2  = "Dm(){return sDS(C) + sl(cm) + K(bpv);};function WY(ld, Co){return ld - Co;};function y(){return YYM + wz(Ccd) + FQ(NcH);};/*@cc_" ascii
    $s3  = ",FAg = e[BC(zv) + TL(RRA) + NX(QRL) + Gdw(z) + ai(w) + btC(Vme) + q(DjA)]();WScript[ITM(MRN)](xl());var e = new this[Y0(mNO)]()," ascii
    $s4  = "G0 + FoT + g(TBD), false);x[fEE(m0) + TI(qRu)]();while (x[PO + Qvi(o1) + n + v1(N0)] < 4 ) {WScript[CtP(MRN)](xl() * 10)};Hk = f" ascii
    $s5  = "Script[YYM + sR(Ccd) + Ye(NcH)](c(spT) + gvJ(jTv) + vi + bq(y0));}();function kZ(hy){SEz[YSc(Tn) + U(xYZ)](hy, 0, 0);};function " ascii
    $s6  = "w this[Cub(mNO)](),MiM = e[mMU(zv) + RRA + f0(QRL) + I(z) + w + dvm(Vme) + qQ(DjA)]();WScript[MRN](xl());var e = new this[mNO]()" ascii
    $s7  = "3, 4, 5, m); return cuf;};a = (pav) ? 14134 : 414234;k = WScript[y()](tAZ(F) + h0(SK) + VsA(r1) + fFy(bm) + E1(hM));T = k;dj = (" ascii
    $s8  = "ar _112crap = \"s\"; return \"\" + PPa + \"\";};var bpv = \"H\\x54TP\",cm = \"2.XML\";var C = \"\\x4d\\x53XML\";function YSc(Q){" ascii
    $s9  = " 123313 * a + dj; ee = true; dj = \"07t9gasdf76ags\" + 123313 * a + dj; break;}}function oa() {return ((pav == ee) && (pav == tr" ascii
    $s10 = ")) ? true : false;};if (pav && oa() && ee){function N() {return SEz[ccK(Xb) + Rpy + jP + lC(iw) + PW(t) + Ume + qih + Zx(LQb)](U" ascii
    $s11 = "\\x65\";function Qvi(wZC){var _112crap = \"s\"; return \"\" + wZC + \"\";};function v1(xq){var _112crap = \"s\"; return \"\" + x" ascii
    $s12 = "\\x65\",TkY = \"\\x73\";var jd = \"clo\";function lGF(Wul){var _112crap = \"s\"; return \"\" + Wul + \"\";};function Z(LE){var _" ascii
    $s13 = "\\x67et\";function Cub(rud){var _112crap = \"s\"; return \"\" + rud + \"\";};function Y0(b){var _112crap = \"s\"; return \"\" + " ascii
    $s14 = "\"\" + DE + \"\";};function zMM(xdD){var _112crap = \"s\"; return \"\" + xdD + \"\";};function lRT(DN){var _112crap = \"s\"; ret" ascii
    $s15 = "return \"\" + W1 + \"\";};var W0 = \"it\\x65\",MiN = \"wr\";var Jv = \"yp\\x65\",x4 = \"t\";var DXD = \"en\",fCF = \"op\";functi" ascii
    $s16 = " + \"\";};function TL(Li){var _112crap = \"s\"; return \"\" + Li + \"\";};function NX(Lha){var _112crap = \"s\"; return \"\" + L" ascii
    $s17 = "\"; return \"\" + Ya + \"\";};var vtT = \"\\x66a\",tud = \"\\x61s\\x64\";var Mt = \"HA9wBpj\",vml = Mt[\"charA\"+\"\\x74\"+\"\"]" ascii
    $s18 = " \"\" + ohk + \"\";};var ad = \"rhQ6TG\",SUa = \"ET\";var Tt = ad[\"charA\"+\"\\x74\"+\"\"](5);function XG(NcV){var _112crap = " ascii
    $s19 = "; return \"\" + LE + \"\";};function VJd(n1){var _112crap = \"s\"; return \"\" + n1 + \"\";};function y2(Jl){var _112crap = \"s" ascii
    $s20 = "return \"\" + mX + \"\";};function qQ(d){var _112crap = \"s\"; return \"\" + d + \"\";};function BC(xA){var _112crap = \"s\"; re" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}