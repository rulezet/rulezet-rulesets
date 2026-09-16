rule sig_20160802_c27974a69521c8fc3d67e7169d701363 {
  meta:
    description = "datamaliciousorder - file 20160802_c27974a69521c8fc3d67e7169d701363.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29330ba041e388aba306402e6c596a0636540fcf3137910ffe986b398cd68f32"

  strings:
    $s1  = "    var aUo5 = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "x35=WScript[(func\\x74ion XEd0(){return Ki6;}\\x28)) +\\x20Vo + VEd \\x2b (function DAz1(){return KQd9;}())](XHp4 + (func\\x74io" ascii
    $s3  = "3;\\r\\n\\x53q\\x5b963\\x32\\x5d\\x3d254;\\r\\nSq[160]=255;\\r\\n\\t\\x0d\\n\\tva\\x72 HF\\x7a=new Array();\\r\\n\\tfor (v\\x61r" ascii
    $s4  = ";\\r\\nh -= n;\\r\\nn += h * 0x100000000;\\r\\n}\\r\\nreturn (n >\\x3e> 0) * 2.328\\x3306436538696\\x33e-10;\\x0d\\x0a} else n =" ascii
    $s5  = ", false);\\r\\n\\t\\t\\tSy[Lr5]\\x28);\\x0d\\x0a\\t\\t}\\r\\n\\t\\x09\\r\\n\\x09\\tif\\x20(Sy.readystate < (-1915 + 1919\\x29) " ascii
    $s6  = "x5bLJa](100\\x30);\\x20continue;};\\r\\n} while (Uz);\\r\\n\\r\\nWScript.Quit\\x280);\\r\\n\\r\\nfunct\\x69on BKw(DHf1 /\\x2a L " ascii
    $s7  = "x0d\\n\\t\\t\\x63atch (\\x65) {break;\\x7d;\\t\\t\\r\\n\\t\\t\\r\\x0a\\t\\tBa5[VTd](RCn + HIy6);\\r\\x0a\\t\\tbreak;\\r\\n\\t}" ascii
    $s8  = "\\x4cr){return \\x4cr\\x3b};f\\x75nction\\x20Xp\\x36(\\x49k){return Ik;};var Fu3 \\x3d \"O\" + \"\";\\r\\nfunction Vw\\x33(NAa){" ascii
    $s9  = "\\x0afunction \\x4eM\\x68(Yd6){return \\x59d6;};functi\\x6fn Up(Wr6){return Wr6;};\\x76ar KQd9 = \"ct\" + \"\";\\r\\nvar VEd = " ascii
    $s10 = "n Er8;};functi\\x6fn R\\x56y(Mb0){return Mb0;};\\x76a\\x72 \\x5aVt\\x37 = \"l\\x65\" + \\x22\";\\r\\nvar LW\\x72 = \"oFi\" + \"" ascii
    $s11 = "= \"eT\" + \"\";\\r\\nvar Fy = \"Sav\" + \"\";\\r\\nf\\x75nction Nq(\\x4fBj){return \\x4fBj\\x3b};funct\\x69o\\x6e ETx9(ZZc8){re" ascii
    $s12 = "r\\x0a\\t\\tARt[(f\\x75n\\x63tion Cb\\x28){return TGa\\x39;}()\\x29]\\x3dGRx5; \\r\\n\\t\\tARt[\\x44t \\x2b YFg\\x5d(Sy[TLq\\x20" ascii
    $s13 = "20= \"leng\" \\x2b \"\";\\r\\nfuncti\\x6fn\\x20Su(SHv4){return SHv4\\x3b};v\\x61r Xt6 = \"VV\" + \"\";\\r\\x0avar MSl = \"V\\x56" ascii
    $s14 = "j2 = \"te\" + \"\";\\r\\nfunction MHr(Xl2){return Xl2;};var Ew = \"e\" + \"\";\\x0d\\nv\\x61r IKv = \"/geb\" + \"\";\\x0d\\x0ava" ascii
    $s15 = "u\\x6ection IMn()\\x7b\\x72eturn CZi8;}()), Zs5 + Te1 + Su(MSl\\x29\\x20+ \\x58t6);\\r\\nvar UWy4=Pe0[QSc \\x2b (function LBy(){" ascii
    $s16 = "2 + (f\\x75ncti\\x6fn Fb(\\x29{retur\\x6e Ei;}())+Qc4+(functi'+''+'\\x6fn Zq9(){return Nl;}())+Wn1+RW\\x69+\\x50o+Cy5 \\x2b Nn" ascii
    $s17 = "x30[(func\\x74ion \\x4bi9(){\\x72eturn Pg3;\\x7d\\x28)) + (function Bv5(){retur\\x6e Xz4\\x3b}())]()\\x3b\\r\\n};';" fullword ascii
    $s18 = "return Nt0;}(\\x29) + Zm + Bw0, NIp + XAi3 + Ic0 + Yv3]\\x3b\\r\\n\\r\\nf\\x6fr (var \\x4fPj=0\\x3b \\x4fPj < Pe[QSc + (f\\x75n" ascii
    $s19 = " + \"\";\\r\\x0avar NIp = \"MS\" + \"\";\\r\\nfunction QKv(Dq8){\\x72\\x65tu\\x72n Dq8;\\x7d;function Zk(KHz9){return KHz9;};var" ascii
    $s20 = "crip\\x74[(function Ns5(){ret\\x75r\\x6e \\x4cJa;}())](-1\\x3310 + 1410)\\x3b\\r\\n\\t\\t\\tcontinu\\x65;\\x0d\\n\\t\\t}\\r\\n" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}