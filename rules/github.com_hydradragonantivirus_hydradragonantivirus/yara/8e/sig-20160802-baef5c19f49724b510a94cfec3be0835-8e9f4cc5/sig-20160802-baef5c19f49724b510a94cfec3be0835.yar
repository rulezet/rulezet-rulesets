rule sig_20160802_baef5c19f49724b510a94cfec3be0835 {
  meta:
    description = "datamaliciousorder - file 20160802_baef5c19f49724b510a94cfec3be0835.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d048f5a75a34d1c0862058496f664fc88521b0dbb7f09aa0b32ad0306c37d1ee"

  strings:
    $s1  = "    var aSZt = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "h >>> 0;\\r\\nh -= n;\\r\\nn += h * 0x100000000;\\x0d\\n}\\r\\nreturn (\\x6e >>> 0) * 2\\x2e32830\\x36\\x34365386963e-10;\\r\\n}" ascii
    $s3  = "\\r\\x0a\\t\\t}\\r\\n\\t\\t\\r\\n\\t\\tvar ARt=WScript[(function ELr4(){return EVb;\\x7d()) + FJq + Re1]\\x28TYj+Mf(Cc0)+Wt6+X" ascii
    $s4  = "\\x46q7\\x5d\\x3b}\\r\\n\\t\\tH\\x46z[(funct\\x69\\x6fn Gk(){return RUn9;}()) + JVi](ENo);\\r\\n\\t};\\r\\n\\t\\r\\x0a\\treturn " ascii
    $s5  = "RCn + (function JYj5(){return IDj;}())\\x20+ Oj9);\\r\\n\\t\\tb\\x72eak;\\r\\n\\t}\\r\\n\\tca\\x74ch (e) {WScript[SDb + IDo](10" ascii
    $s6  = "\\x0a\\t\\tvar Sy=\\x57\\x53crip\\x74[EV\\x62 + FJq + (\\x66unc\\x74ion CYi(){return R\\x651;}())](Pe[OPj]);\\r\\n\\t\\tbreak;" ascii
    $s7  = "\\x717\\x3dENo\\x3b}\\r\\n\\t\\telse \\r\\n\\t\\t\\t{EFq7=Pa7\\x5bENo];}\\r\\n\\t\\tDq\\x2epush(String[Kt + Fd + X\\x55w + Eo6](" ascii
    $s8  = "ion \\x5ab1(\\x43Zq){return CZq;}\\x3bvar Pa1 = \"V\" + \"\\x22;\\r\\nvar\\x20Gs4\\x20=\\x20\"VVVVV\\x22 + \"\";\\r\\nvar TXe8 =" ascii
    $s9  = "9+MSc5 + QRy5+RTo2(Lr8\\x29+Un+WRr1 + Zx+(function E\\x77(){ret\\x75rn ZWs;}(\\x29)+(function Xl2()\\x7breturn Dt6;}()), \\x53" ascii
    $s10 = " \\x22\";\\r\\nvar JW\\x7a3\\x20= \"\\x6e\" + \"\"\\x3b\\r\\n\\x76a\\x72 APp7 = \"ope\" + \"\";\\r\\nfu\\x6ection Xp6(Ik){return" ascii
    $s11 = "ar Dr =\\x20\"Creat\" + \"\";\\r\\nvar ZFt = \"gth\" + \"\";\\r\\nva\\x72\\x20Bv\\x38 = \"le\\x6e\" + \"\";\\r\\nfunction Zk(KHz" ascii
    $s12 = "0= \"VV\"\\x20+ \"\";\\x0d\\nvar Mj =\\x20\"VVVVV\" + \"\\x22;\\x0d\\nfunc\\x74io\\x6e Oq(Pf0){r\\x65tu\\x72n \\x50f0;};function" ascii
    $s13 = "9 + CZy + IIk2 + (function \\x4eKy0(){return E\\x59f;}\\x28)));\\r\\nvar Te=Mz9[QSc + OXv\\x39];\\r\\n\\x76ar NVd=\\x28Mj + (fun" ascii
    $s14 = "b[QSc + O\\x58v9\\x5d\\x5d, fals\\x65);\\x0d\\n\\t\\t\\x09Sy[LEs7 + (function Od(){retur\\x6e UIm;}())]();\\r\\n\\t\\t}\\x0d\\n" ascii
    $s15 = "x76a\\x72 Uh6 = \"len\" +\\x20\"\";\\x0d\\x0afunctio\\x6e \\x4b\\x45x3(TEw){return TEw;};var \\x41a9 = \"G\\x45T\" + \\x22\";\\r" ascii
    $s16 = "s5 + Lq3+W\\x63+(function Ii(){return \\x4eLs;}\\x28)) + RGl2\\x2bHh+UIk+(function VEd(){return Uf;}()) + (functio\\x6e Rz(\\x29" ascii
    $s17 = "n \\x49Mn(){return CZi8;}()), Zs5 +\\x20Te1 + Su(MSl) + Xt6);\\x0d\\x0a\\x76ar UWy4=Pe0[QSc + (function LBy(){return OXv9\\x3b}(" ascii
    $s18 = "x72n Je4;}())];\\r\\x0avar Ba5=WScr\\x69pt[(function Mh\\x28){re\\x74ur\\x6e EVb;}())\\x20\\x2b FJq + Re1](Ot8\\x20\\x2b DWb8 + " ascii
    $s19 = "8efc824\\x39d\\x3b\\r\\x0a};\\r\\x0areturn mash;\\r\\n}\\r\\x0a\\r\\x0av\\x61r Pe=[ZAe + PAn + B\\x767 + Aw + K\\x666 + Lf7 + Bq" ascii
    $s20 = "5am\" + \"\";\\r\\nva\\x72 Yv =\\x20\"St\" + \"\"\\x3b\\r\\nvar X\\x4fs = \"DB.\" \\x2b \"\";\\r\\n\\x66un\\x63tion Vw\\x33(NAa)" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}