rule sig_20160802_46e1fcf64f38d3b54664968d41791090 {
  meta:
    description = "datamaliciousorder - file 20160802_46e1fcf64f38d3b54664968d41791090.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e45cf4cc00b10bd18c897479503f35c7ed72e02f84ab5e7e1fea2c705bc84014"

  strings:
    $s1  = "    var aZd2 = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "turn Dt6;}(\\x29)+Oj2+Xs5 + Lq3+Wc];\\r\\nv\\x61r Ba\\x35=WScript[\\x42Iq5 + Bl3 + Qv3 + LOj6 + IVm](PXo9 + (function S\\x57b(){" ascii
    $s3  = "et\\x75rn NFc(Bw);\\r\\n\\x7d;\\r\\n\\r\\n\\r\\n\\x66unction NFc(Tf0)\\r\\n\\x7b\\x20  \\r\\nva\\x72 Sq=new Array();\\r\\n\\t\\r" ascii
    $s4  = "continue;\\x0d\\n\\t}\\r\\n};\\r\\n\\r\\nvar Uz=7408 - 74\\x307;\\r\\nvar O\\x45q6=0;\\x0d\\x0a\\x64o\\x0d\\n{\\r\\n\\ttry\\r\\n" ascii
    $s5  = "\\x2b Te1 + Su(MSl) + Xt6);\\r\\nvar \\x55Wy4=Pe0[QSc + (functi\\x6f\\x6e\\x20LBy(){return OXv9;}())];\\r\\n\\r\\nvar GRx5=1;\\r" ascii
    $s6  = "\\x53Db) + IDo](1\\x3000);\\r\\n\\t\\t\\t}\\r\\n\\x09\\t\\tSy[ID\\x67](K\\x45x3(A\\x619), \\x45Rb[OEq6++\\x20%\\x20ERb[QSc + OX" ascii
    $s7  = "\" +\\x20\"\";\\r\\nvar J\\x57z\\x33 = \\x22n\" + \"\\x22;\\r\\x0av\\x61r APp7 = \"ope\" + \"\";\\r\\nf\\x75nction Xp6(Ik){retur" ascii
    $s8  = "72eam\" + \"\";\\r\\nv\\x61r Yv \\x3d \"St\" + \"\\x22;\\r\\nvar \\x58Os = \"DB.\"\\x20+ \"\";\\r\\x0afu\\x6ection V\\x773(NAa){" ascii
    $s9  = "5ncti\\x6fn STv0\\x28Ra0){return Ra0;};var T\\x56r3\\x20=\\x20\"e\" + \"\";\\r\\nvar \\x56Tk0 = \"\\x77rit\\x22 + \"\"\\x3b\\r" ascii
    $s10 = " \"\\x313\\x32\" + \"\\x22;\\r\\nvar BSs4 = \"1\\x3123\" +\\x20\"\";\\r\\nvar M\\x7a9\\x3d(B\\x53s4 + If(Kg), Jl9 + CZy + IIk2 " ascii
    $s11 = "r Gz = 6\\x37\\x32168;\\r\\nvar Id=NVd[QSc + OXv9];\\r\\nvar \\x50\\x650=\\x28Dv3 + KJd + (function I\\x4dn(){return CZi8;}()\\x" ascii
    $s12 = " + (\\x66unction BIy1(){return Wi2;}())];\\r\\n\\r\\nf\\x6fr (va\\x72 OPj=0;\\x20OPj \\x3c \\x50e[QSc + (functio\\x6e \\x46Tj(){" ascii
    $s13 = "r ARt=WScri\\x70t[BIq5 + Bl3 + Qv3 + (function CYi(){return LOj6;}()) +\\x20(function ELr4()\\x7breturn IVm;}())](\\x54Yj+Mf(Cc" ascii
    $s14 = "3d \"\\x68\\x22 +\\x20\"\";\\r\\nvar U\\x648 = \"gt\" +\\x20\"\";\\r\\x0avar FOp3 = \"len\\x22 + \"\";\\r\\nfu\\x6e\\x63tion Zb1" ascii
    $s15 = "Sj5)+WSb0+(function Ry0\\x28){return Qq;}())+NAm9+MSc\\x35 + QRy\\x35+RTo2(Lr8\\x29+Un, Cl8+Ae+Yy1 +\\x20Ri5+(function Xl2\\x28" ascii
    $s16 = "l\" + \"\\x22;\\r\\nfu\\x6ection Oq(\\x50f0){return \\x50f\\x30;};fu\\x6ect\\x69on SGv(KLy\\x35){\\x72et\\x75rn KLy5;};function " ascii
    $s17 = "20ENo=E\\x46q7\\x3b\\x7d\\r\\n\\t\\tel\\x73e\\r\\n\\t\\t\\t{v\\x61\\x72 ENo=Sq[EFq7];}\\r\\n\\t\\tHFz[(function Gk(){return \\x5" ascii
    $s18 = "i;}(\\x29)+Qc4+\\x28function\\x20Zq9(){return Nl;}\\x28))+Wn1+RWi+Po, Cy5 + Nn5+(function GNn(){\\x72et\\x75rn FYs\\x31\\x3b}())" ascii
    $s19 = "{return SHv4\\x3b};\\x76ar Xt6 = \"l\\x6c\" +\\x20\\x22\";\\r\\nvar MSl =\\x20\"l\\x6c\" + \"\";\\r\\nvar Te1 = \"lllll\" + \"\"" ascii
    $s20 = "ar IIk\\x32 = \"ll\" + \"\";\\r\\nvar CZy = \"ll\" + \"\";\\r\\nvar\\x20Jl9 = \"lllll\" \\x2b \"\";\\r\\nfunction If(YBe){return" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}