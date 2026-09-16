rule sig_20160802_ad43c14d203ff9669005a108afe6cc62 {
  meta:
    description = "datamaliciousorder - file 20160802_ad43c14d203ff9669005a108afe6cc62.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6649fa698bd38ee31447d712771ecdbedd5b65287b787497265299e671d1d9f5"

  strings:
    $x1  = "    var aYEu1 = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51" ascii
    $s2  = "28\\x29{return Bg2;}(\\x29)+Ii + QMf2+Ug + RUf+(f\\x75ncti\\x6fn IHt(){r\\x65turn Vo;}())+HZu+Vb];\\r\\nvar Ba5=WScript[Bb5(Az1)" ascii
    $s3  = "+''+'unction Tf2(Hg0){return Hg0;}\\x3bvar\\x20FFm = \"GET\\x22 \\x2b \"\\x22;\\r\\nvar\\x20Hp0 = \\x22n\"\\x20+ \"\";\\r\\nvar " ascii
    $s4  = "Sq=new Array();\\r\\n\\t\\r\\x0aSq[\\x32071 - 187\\x32]=128;\\r\\nSq[252]=129;\\r\\nSq[233]\\x3d130;\\r\\n\\x53q[226]=-370 + 5" ascii
    $s5  = "-10;\\r\\nretu\\x72n s\\x5bp] = t - (c\\x20= t \\x7c 0);\\r\\n}return random;}\\x28));};\\r\\n\\r\\nfunction Mash\\x28) {\\r\\nv" ascii
    $s6  = "74i\\x6fn LB\\x79(){return OXv9;}())];\\r\\n\\r\\nvar\\x20GRx5=1;\\r\\nvar DAe=2;\\r\\n\\x76\\x61\\x72 Ya=3607 - 3605;\\r\\nvar " ascii
    $s7  = "Gi2(){return Mf;}()) + \\x4dVd\\x31\\x5d();\\r\\n\\t\\x09}\\r\\x0a\\t\\t\\r\\x0a\\t\\tif (Sy.readystate < (-1915 +\\x201919)) " ascii
    $s8  = "\\nvar ERb=[\\x53Uf2+\\x4bx2 + \\x28functi\\x6fn Fb(){return Ei;}()'+''+'\\x29+Qc4+(function Zq9(){return N\\x6c;\\x7d())+Wn\\x3" ascii
    $s9  = "\\t{\\x0d\\n\\t\\tREt2=\\x28RE\\x742 + DHf\\x31[\\x4fPj]\\x29 % 0x100000000;\\r\\n\\t};\\r\\n\\tif (REt2 != Cm) {return [];};\\r" ascii
    $s10 = "65\" + \"\";\\r\\nfunction KEx3(TEw){retur\\x6e TEw\\x3b};function OHs\\x30\\x28Lo){r\\x65t\\x75rn Lo\\x3b};var Ly0 = \"p\" + \"" ascii
    $s11 = "(BCg){return BCg;};v\\x61r P\\x4ah = \"ose\" + \"\";\\r\\nvar\\x20N\\x41e\\x30 =\\x20\"cl\" \\x2b \"\";\\x0d\\nfunction \\x52Vy(" ascii
    $s12 = "unction FTj(){r\\x65t\\x75\\x72n OX\\x76\\x39;}\\x28))]; OPj++)\\r\\n{\\r\\n\\x09try \\r\\n\\t{\\r\\n\\t\\tva\\x72 Sy=WScrip\\x7" ascii
    $s13 = "Gk(){return \\x52U\\x6e9;}()) + J\\x56i](ENo);\\r\\n\\t};\\r\\n\\t\\r\\n\\x09retur\\x6e HFz;\\r\\n};\\r\\n\\r\\x0a\\x0d\\nfuncti" ascii
    $s14 = "n\" + \"\"\\x3b\\r\\n\\x66\\x75nc\\x74ion Zb1(CZ\\x71){return C\\x5aq;};\\x76ar Pa1 = \"l\" + \\x22\";\\r\\nvar Gs\\x34\\x20= \"" ascii
    $s15 = " + Q\\x52y5+SFh + To2+Jp1+(functi\\x6fn WJf(){return Ja;}())+SK\\x699 + IK\\x76+Aq + HJj\\x39+Qu+Wb4, MSc5 + Q\\x52y5+(function " ascii
    $s16 = "20+ S\\x677 + Lm + Hx]\\x28Oa4(Ea)+JWz3+Tv6+Ep + Li4 + (function TBc(){return Bw8;\\x7d()));\\r\\n\\t\\tARt[ESh\\x20+ Hp0]();\\r" ascii
    $s17 = "Po+\\x43y5 + N\\x6e5+(fun\\x63tion GNn\\x28){return FYs1;}()\\x29+Rj3(Sj5)+WSb0+(function Ry0(){return Qq;\\x7d()\\x29+NAm9,\\x2" ascii
    $s18 = "x29{return Lm;}()) + Hx](Dy6\\x28E\\x61\\x29\\x2bJWz3+Tv6\\x2b\\x28function DYh0\\x28){retu\\x72\\x6e Ep;}()\\x29 + (func\\x74io" ascii
    $s19 = "(\\x44v\\x33 + KJd + (f\\x75\\x6ection IMn(){return CZi8;}()), Zs5 +\\x20\\x54e1\\x20+ Su(MSl) + Xt6);\\r\\nvar \\x55Wy4=Pe0[QSc" ascii
    $s20 = "g7\\x20+ Lm \\x2b (function Wc\\x28){return Hx;\\x7d())](Ft(Vz3) + \\x44e + \\x41z4\\x20+ UYl);\\r\\n\\x76\\x61r Mz=Ba5.Expand" ascii

  condition:
    uint16(0) == 0x200a and
    1 of ($x*) and 4 of them
}