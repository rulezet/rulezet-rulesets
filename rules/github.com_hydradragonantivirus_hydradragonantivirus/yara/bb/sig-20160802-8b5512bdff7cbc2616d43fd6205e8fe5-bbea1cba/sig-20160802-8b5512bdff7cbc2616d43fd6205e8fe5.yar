rule sig_20160802_8b5512bdff7cbc2616d43fd6205e8fe5 {
  meta:
    description = "datamaliciousorder - file 20160802_8b5512bdff7cbc2616d43fd6205e8fe5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb0e335942ceb3fb84c6ca8d4f57a2ccfdb10891acdee5af43f9dc74f63fe9de"

  strings:
    $s1  = "    var aTEr = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "x20\\x58l2(){return Dt\\x36;}())+Oj2+Xs5 + Lq3+Wc+\\x28func\\x74ion Ii(){\\x72eturn Ls;}()) + RGl2];\\r\\nvar Ba5=WScript[Vq + L" ascii
    $s3  = "n\\t\\tvar \\x41Rt=\\x57Script[Vq + \\x49Vm + (function CYi(){return Yk;}()) + (function ELr4(){\\x72eturn Jr;}())](T\\x59j+Mf(C" ascii
    $s4  = "x\\x3100000000;\\r\\n}\\r\\nreturn (n >>> 0) * 2.32830643653869\\x363e-10;\\r\\n} el\\x73e n = 0xefc\\x38249d;\\x0d\\x0a};\\r\\n" ascii
    $s5  = "ar OPj=693\\x38 - 69\\x338; OPj < Tf0[\\x4aQu(QS\\x63) +\\x20(fun\\x63ti\\x6fn Cn2(){return \\x4fX\\x769;}())\\x5d;\\x20OPj++)" ascii
    $s6  = "1768863 \\x2a s[p\\x5d + c \\x2a 2.32\\x38306436538696\\x33e-10;\\r\\nre\\x74urn s[p] =\\x20t - \\x28\\x63 = t | 0);\\r\\x0a\\x7" ascii
    $s7  = "se\\r\\n\\t\\t\\t\\x7bvar E\\x4eo=Sq[\\x45Fq\\x37\\x5d;}\\r\\n\\t\\t\\x48Fz[(func\\x74\\x69on Gk(){return RUn9;}()) + JVi](ENo);" ascii
    $s8  = "15[ILh6 +\\x20Et\\x31](RCn + (function JYj5(){return IDj;}()) +\\x20Oj9);\\r\\n\\t\\tbre\\x61k;\\r\\n\\t}\\r\\n\\tcatc\\x68 (e) " ascii
    $s9  = "\\x6fn\\x20IMn(\\x29{return CZi8;}()), Zs5 + Te1\\x20+ Su(MSl) + Xt6);\\r\\nva\\x72\\x20\\x55Wy4=Pe0[QSc + (function LBy(){retur" ascii
    $s10 = "\" +\\x20\"\";\\r\\nvar J\\x57z\\x33 = \\x22n\" + \"\\x22;\\r\\x0av\\x61r APp7 = \"ope\" + \"\";\\r\\nf\\x75nction Xp6(Ik){retur" ascii
    $s11 = "72eam\" + \"\";\\r\\nv\\x61r Yv \\x3d \"St\" + \"\\x22;\\r\\nvar \\x58Os = \"DB.\"\\x20+ \"\";\\r\\x0afu\\x6ection V\\x773(NAa){" ascii
    $s12 = "5ncti\\x6fn STv0\\x28Ra0){return Ra0;};var T\\x56r3\\x20=\\x20\"e\" + \"\";\\r\\nvar \\x56Tk0 = \"\\x77rit\\x22 + \"\"\\x3b\\r" ascii
    $s13 = " \\x3d \"\\x6fvf\" + \"\";\\r\\n\\x76ar PIz0 = \"6Y\"\\x20+ \"\";\\r\\nvar \\x47Md3 = \\x22sv\" + \"\";\\r\\nfunction Jn9(J\\x6d" ascii
    $s14 = "77 = \"\\x6cl\" + \"\\x22;\\r\\nva\\x72 Mj = \"ll\\x6cll\" + \"\";\\r\\n\\x66u\\x6ection\\x20Oq\\x28Pf0){retur\\x6e P\\x660;\\x7" ascii
    $s15 = "a0) + (function\\x20Ix6(){return E\\x54x9;}()\\x29\\x20+\\x20Z\\x5ac8](RJ\\x702, Ya);\\r\\n\\t\\t\\x41Rt[DEk0\\x28KCh5) + TZa + " ascii
    $s16 = "Vm)\\x20+ Yk \\x2b (function ZO\\x639(){return J\\x72;}())](Ot8 + DW\\x628 + \\x53Sq\\x29;\\r\\nvar Mz\\x3d\\x42a5.ExpandEnviro" ascii
    $s17 = "\" + \"\";\\r\\nfu\\x6ec\\x74io\\x6e LFp(As3){retu\\x72n As3;\\x7d;function FJq(Re1){\\x72\\x65tur\\x6e Re1;}\\x3b\\x66unction U" ascii
    $s18 = "\"\";\\r\\nvar Cl8 ='+''+' \"t\\x70:\\x2f\" + \"\";\\r\\x0avar Un = \"ht\" + \"\";\\x0d\\nfunctio\\x6e RTo2(X\\x681){return Xh" ascii
    $s19 = "), Jl9 +\\x20CZy + IIk2 + (function NKy0\\x28){return EYf;}\\x28)))\\x3b\\r\\nvar Te=Mz9[QSc + OXv9];\\r\\x0avar \\x4eVd=(Mj \\x" ascii
    $s20 = "2+Kx\\x32 + (fu\\x6ection \\x46b(){retu\\x72n Ei;}())+Qc4+(fu\\x6ection Zq9(){return Nl;}())+Wn1+RWi+Po+Cy5\\x20+ \\x4en5+YTe\\x" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}