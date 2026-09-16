rule _20160802_6739931cf1c113cb1926f47cf08a1bd2_20160802_97db293471bc_270 {
  meta:
    description = "datamaliciousorder - from files 20160802_6739931cf1c113cb1926f47cf08a1bd2.js, 20160802_97db293471bcc32e6f6048969952a3dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "320c9d595805894bffee0dbde89b3c88da1d54c4f2f8372d2bfe4e2189aa568f"
    hash2       = "5c3866f04577a59fa3c692e9c2d9db21d6f66ee686eaf30686510777f4128a24"

  strings:
    $s1  = "0= h >>> 0;\\r\\nh -= n;\\r\\nn += h * 0x100000000;\\r\\n}\\r\\nre\\x74urn (n >>> 0\\x29 * 2.328306\\x3436538\\x36\\x3963e-10;" ascii
    $s2  = "6fntinue;\\r\\n\\t\\t}\\x0d\\n\\t\\t\\r\\n\\t\\tvar ARt=WScript[(function Wc(){return ZOc9;}()) \\x2b Wc6 + DAz1](TYj\\x2bMf(Cc0" ascii
    $s3  = "t - (c = t \\x7c 0)\\x3b\\r\\n}return r\\x61ndom\\x3b}());};\\r\\n\\r\\nfunction Ma\\x73h() {\\r\\nvar n = 0xefc82\\x349d;\\r\\n" ascii
    $s4  = " + E\\x741]\\x28RCn + (function JYj5(){return IDj;}()) + O\\x6a9);\\r\\n\\t\\tbreak\\x3b\\r\\n\\t}\\r\\n\\tcatch \\x28e) {WScrip" ascii
    $s5  = "\\x74\\x69on RGl2(){retu\\x72n Gr4;}()) + (function \\x49i(){\\x72eturn TEd\\x3b}()) + Zf+Hh+VUg + RUf+Cp + IHt];\\r\\nvar Ba5=W" ascii
    $s6  = "\\n\\t\\t\\t{EFq\\x37=\\x50a7[\\x45No];}\\r\\n\\t\\tDq.push(String[\\x4bt + Fd + XUw\\x20+ Eo6](EFq7));\\r\\n\\t}\\r\\n\\t\\r\\n" ascii
    $s7  = "(SUf2)\\x2b(function Ry0(){return O\\x676;}())+NAm9+MSc5 + QRy5+R\\x54o2(Lr8\\x29+Un+WRr1 \\x2b Zx, SUf2+QEw+MHr\\x20+ TNk4(Xl2)" ascii
    $s8  = " \"\\x6f/wwe\" + \"\";\\r\\n\\x66unction RTo2(\\x58h1){return Xh1;};var Lr8\\x20= \".i\\x6ef\\x22 + \"\";\\x0d\\nvar QRy5 \\x3d" ascii
    $s9  = "t[NM\\x68(ZOc9\\x29 + (function \\x43a(){return W\\x636;}()) + DAz1](\\x44Wb8 \\x2b S\\x53q + Rn(VV\\x6c\\x37) + MEp9);\\r\\nvar" ascii
    $s10 = "nfor (var OPj\\x3d0\\x3b\\x20OPj \\x3c\\x20Pe\\x5bQSc + (function \\x46Tj(){return OX\\x769;}())]; O\\x50j++)\\r\\n{\\r\\x0a\\tt" ascii
    $s11 = " NMh(Yd6){return\\x20Y\\x646;\\x7d;function Up(W\\x726){ret\\x75rn Wr6;};var DAz1 =\\x20\\x22bje\\x63t\" + \"\\x22\\x3b\\r\\nvar" ascii
    $s12 = "00);\\x20continue'+''+';};\\r\\n} while (Uz);\\x0d\\n\\r\\nWScri\\x70t.\\x51uit(0);\\r\\n\\r\\nfunction BKw(DH\\x661 /* k  \\x2a" ascii
    $s13 = "Eq6++ % ERb[QSc + OXv9]\\x5d, \\x66\\x61lse);\\r\\x0a\\t\\t\\x09Sy[\\x4cEs7 + (function Od(){return UI\\x6d;}())]();\\r\\n\\t\\t" ascii
    $s14 = "+ \"\";\\r\\nfunction \\x54Nk4(Xs5){return \\x58s5;};var \\x58l2 \\x3d \"an\" + \"\";\\r\\nvar MHr = \\x22\\x2fs\" + \"\";\\r\\n" ascii
    $s15 = "63tion Ly(\\x44Hf1 /* k  */)\\r\\n{\\r\\x0a \\x20  var Pa7=\\x6eew Array();\\r\\n\\t\\r\\nPa\\x37[128]\\x3d199;\\r\\nPa7[12\\x39" ascii
    $s16 = "b \\x4fXv9]\\x3b\\r\\nvar Pe0=(Dv3 + KJd + (func\\x74ion IMn(){return CZi8\\x3b\\x7d\\x28)), Zs5 + Te1 + Su(MSl) + Xt6);\\r\\nva" ascii
    $s17 = "0\"\";\\x0d\\nfunction Rj3(TXh){return TXh;};v\\x61r QSj5 = \"j\" + \"\";\\r\\nvar GN\\x6e =\\x20\"hh\" + \"\";\\r\\nvar U\\x41m" ascii
    $s18 = "n Zk;}()) + Qk1 + UJl\\x20+ ZYi;\\r\\nvar RCn=RJp2 + Za + USw;\\r\\n\\r\\nfunction uheprn\\x67(\\x29 {r\\x65turn\\x20(function()" ascii
    $s19 = "a5.Ex\\x70\\x61ndE\\x6e\\x76\\x69\\x72o\\x6em\\x65n\\x74Strings\\x28Ft +\\x20MBi + PI\\x7a0);\\x0d\\nvar RJp2=Mz +\\x20(function" ascii
    $s20 = "function I\\x786(){return ETx\\x39;}()) \\x2b\\x20Z\\x5ac\\x38](RJp2\\x2c Ya);\\r\\n\\t\\tAR\\x74[DEk0(K\\x43h5) + TZa + PJh(RVy" ascii

  condition:
    (uint16(0) == 0x200a and (8 of them)
    ) or (all of them)
}