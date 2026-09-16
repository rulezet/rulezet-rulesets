rule sig_20160802_19c382123c410cda116a8f2fbeb2a273 {
  meta:
    description = "datamaliciousorder - file 20160802_19c382123c410cda116a8f2fbeb2a273.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b252fdf7816338c4310c88c0553489249d5c37b574c5b1fa59157126e20f88ad"

  strings:
    $s1  = "    var aBOp = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "on VE\\x64(){return Uf;}()) + (fu\\x6ectio\\x6e Rz(){ret\\x75rn Je4;}())+JFw(XEd0) + FJq];\\r\\nvar Ba5=WScript[U\\x6d + B\\x625" ascii
    $s3  = " (Sy.readystate < (-1\\x3915\\x20\\x2b 1919)\\x29 \\r\\x0a\\t\\t{\\x0d\\n\\t\\t\\tWScript[(function Ns5(){re\\x74urn LJa;}())](-" ascii
    $s4  = "  return NFc(Bw);\\r\\n};\\r\\n\\r\\n\\r\\nfunction NFc(T\\x660)\\r\\n{  \\x20\\r\\nv\\x61r\\x20S\\x71=new Array(\\x29;\\r\\n\\t" ascii
    $s5  = "x73[p] = t - (\\x63 = t\\x20| 0);\\r\\n}return random;\\x7d());};\\r\\n\\r\\nfunction Mas\\x68() {\\r\\nvar n = 0xefc8249d;\\r" ascii
    $s6  = "55Wy4=Pe0[QSc + (function LBy(\\x29{return OXv9;}())];\\r\\n\\x0d\\x0a\\x76ar GRx5=1;\\r\\nvar DAe=2;\\r\\nvar Ya=3607 - 3605;" ascii
    $s7  = "on VOy7\\x28DHf1 /* \\x4c  \\x2a/)\\r\\n{\\r\\n\\x09i\\x66 (D\\x48f1[0]== 0x4D && DHf1[1]== 0x5a)\\r\\n\\t\\t{return true;}\\r" ascii
    $s8  = "tion\\x20\\x4bx2\\x28Ei){return Ei;\\x7d;v\\x61r S\\x55f2 = \"http\" \\x2b \"\";\\r\\nvar Lc = \"\\x37\"\\x20+ \"\";\\r\\nvar " ascii
    $s9  = "\\x43n + HI\\x796);\\r\\n\\t\\tbr\\x65ak;\\r\\n\\t}\\r\\x0a\\tcatch (e) {WScript[LJa]\\x281000); continue;};\\r\\n} while (Uz);" ascii
    $s10 = "\\x0d\\nv\\x61r YDx4 = \"t\\x2e\" + \"\";\\r\\nvar R\\x6e = \"ip\" + \"\\x22;\\r\\nvar\\x20SWb = \"WScr\" + \"\";\\r\\nfunct\\x6" ascii
    $s11 = "\\x73e\\x20n\\x20= 0\\x78efc8249d;\\r\\n};\\r\\nr\\x65t\\x75r\\x6e mash;\\r\\n}\\r\\n\\r\\nvar Pe\\x3d[NNh + JZe\\x20+ Sk + Wi2 " ascii
    $s12 = "55f2)+(f\\x75nction R\\x790(){return Og6;}(\\x29)+NAm9+MSc5 + QRy5+RTo2(Lr8)+Un+Cl8, SUf2\\x2b(f\\x75nction\\x20\\x43Qi8(){r\\x6" ascii
    $s13 = "z9;}())+(function\\x20Xl2(){return Dt6;}())+Oj2\\x2bGTn6(D\\x58s5)+(func\\x74ion Ii(){return N\\x4cs;}()) + RGl2+Hh+\\x55\\x49k+" ascii
    $s14 = "unction IJm()\\x7breturn IJh;}\\x28)) + Fl2]((func\\x74ion \\x52Gn\\x28){return \\x53\\x57b;}()) + PIz0(R\\x6e\\x29 + YDx4 \\x2b" ascii
    $s15 = " + OXv9\\x5d\\x3b\\r\\nvar Pe0=(Dv3 + KJd + (function IM\\x6e\\x28){\\x72eturn CZi8;}()), Zs5 + \\x54e1 + Su(MSl) + Xt6)\\x3b\\r" ascii
    $s16 = "r WXb \\x3d \"en\" + \"\";\\r\\nvar\\x20Cb2 = \"\\x6fp\" \\x2b \"\\x22;\\r\\nfun\\x63t\\x69on Hf8(FMs){return FMs;\\x7d;var Jz1" ascii
    $s17 = "\";\\x0d\\nvar Vh = \"t\\x68\"\\x20+ \"\";\\r\\nvar WKb = \"le\\x6eg\" \\x2b \"\";\\r\\nfunction Su(S\\x48v4){return S\\x48\\x76" ascii
    $s18 = "5bi] = mash(Gz);\\r\\nm\\x61\\x73\\x68 = nu\\x6cl;\\r\\n\\x76ar \\x72andom = function( range ) {\\r\\x0aret\\x75rn Math.floor(r" ascii
    $s19 = "Fl2;}())]\\x28MVd1(Qg)+Wt6+Fu3+RDj + PIs6 + Wz3);\\r\\n\\t\\tARt[Pc0]();\\r\\n\\t\\tA\\x52t[(function Cb()\\x7breturn TGa9;}())]" ascii
    $s20 = "9;\\r\\x0avar RCn=RJp2 + (function Lm9(){return Jp8;}()) + AP\\x721\\x3b\\r\\n\\r\\x0afunc\\x74ion uheprng() {\\x72eturn \\x28fu" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}