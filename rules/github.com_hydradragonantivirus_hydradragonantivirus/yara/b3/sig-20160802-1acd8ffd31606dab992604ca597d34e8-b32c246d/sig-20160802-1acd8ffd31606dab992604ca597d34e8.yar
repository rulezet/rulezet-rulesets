rule sig_20160802_1acd8ffd31606dab992604ca597d34e8 {
  meta:
    description = "datamaliciousorder - file 20160802_1acd8ffd31606dab992604ca597d34e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "208319c0994b6153a28d07c6cad80e1fb338e2d7f0d4cb3728ee8c9817a2ccf3"

  strings:
    $x1  = "    var aLBm = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "53;\\x0d\\x0a\\x53q[9632]=254;\\r\\nSq[160]\\x3d255;\\x0d\\n\\t\\r\\x0a\\tvar HFz=new Array();\\r\\x0a\\tfor (var OPj=\\x36938 -" ascii
    $s3  = "\\x20KJd + (function IMn(){return\\x20CZi8;}()), Zs5 + Te1 \\x2b\\x20\\x53u(MSl) + Xt6);\\r\\nvar UWy4=Pe0[QSc + (function \\x4c" ascii
    $s4  = "\\t{\\r\\n\\t\\tREt2=(REt2\\x20+ DHf1[OP\\x6a]) % 0x100000000\\x3b\\r\\n\\t};\\x0d\\n\\tif (REt2 !=\\x20Cm) {return [];};\\r\\n" ascii
    $s5  = "\\x3b\\r\\nvar\\x20EGw = \"VV\\x22 + \"\";\\r\\nvar\\x20M\\x6a = \"V\\x56VV\\x56\" + \"\";\\r\\nf\\x75nc\\x74io\\x6e Oq(Pf0){ret" ascii
    $s6  = "\\x4cr){return \\x4cr\\x3b};f\\x75nction\\x20Xp\\x36(\\x49k){return Ik;};var Fu3 \\x3d \"O\" + \"\";\\r\\nfunction Vw\\x33(NAa){" ascii
    $s7  = "b \\x4f\\x50j < \\x50\\x65[Q\\x53c + (function FT\\x6a(){return OXv9\\x3b}())]; OPj\\x2b+)\\r\\n{\\r\\n\\t\\x74ry \\x0d\\x0a\\t{" ascii
    $s8  = "+ Nn5+(function GNn(){\\x72eturn FYs1;}()), Rj3(Sj5)\\x2bSb0+(f\\x75nction Ry\\x30(){return Qq;}())\\x2bNAm9+MSc5 + QRy5+\\x52" ascii
    $s9  = "n Er8;};functi\\x6fn R\\x56y(Mb0){return Mb0;};\\x76a\\x72 \\x5aVt\\x37 = \"l\\x65\" + \\x22\";\\r\\nvar LW\\x72 = \"oFi\" + \"" ascii
    $s10 = "ction Rj3(TXh){return TX\\x68;};var Sj5 = \"htt\" + \"\";\\r\\n\\x76ar\\x20FYs1 = \"s5z\" + \"\"\\x3b\\r\\nvar Nn\\x35\\x20= \"m" ascii
    $s11 = "n}\\x20e\\x6cs\\x65 n \\x3d 0xefc8249d;\\r\\n};\\x0d\\n\\x72e\\x74urn mash;\\r\\n}\\r\\n\\r\\nvar\\x20Pe=[Lf7 + \\x28function Ra" ascii
    $s12 = "s4 + If(Kg), Jl9 + CZy + \\x49Ik2 + (functio\\x6e NK\\x790(){return EYf;}()));\\r\\nvar\\x20Te=M\\x7a9[QSc +\\x20OXv9];\\r\\nvar" ascii
    $s13 = "ML\" \\x2b \"\";\\r\\nvar Sy8 = \"ML\" + \"\";\\r\\nvar IFc4 = \"\\x4d\\x53X\"\\x20+ \"\";\\r\\x0afunction QKv(Dq8){return Dq8;}" ascii
    $s14 = "{return K\\x48z9;};var Nt0 = \"\\x35.1\" +\\x20\"\";\\r\\nvar YWl7 = \"t.\" + \"\";\\r\\n\\x76ar Ki5 \\x3d \\x22ques\" + \"\";" ascii
    $s15 = "3c Tf0[JQu(QSc) + (function Cn2(){r\\x65turn OX\\x76\\x39;}())]; OPj++)\\r\\n\\t{\\r\\n\\x09\\t\\x76\\x61r EFq7=Tf0[S\\x4de3 + E" ascii
    $s16 = "20+ \"\\x22;\\r\\nfunction Zb1(\\x43Zq){return CZq;};\\x76ar Pa1\\x20= \"\\x56\"\\x20+ \"\";\\r\\x0avar Gs4 = \"VVVVV\" + \"\";" ascii
    $s17 = "= \"eT\" + \"\";\\r\\nvar Fy = \"Sav\" + \"\";\\r\\nf\\x75nction Nq(\\x4fBj){return \\x4fBj\\x3b};funct\\x69o\\x6e ETx9(ZZc8){re" ascii
    $s18 = "r8)+Un+Cl8\\x2bAe+Yy1 + Ri5+(function \\x58l2()\\x7breturn Dt\\x36;}())+Oj2+GTn6(Xs5), Sj5+RGl2 + WRl3+Oj6 + IVm+E\\x72+(fu\\x6e" ascii
    $s19 = "+ (functio\\x6e Pj2(){return GOk;}()) + CLc9;\\r\\nvar RCn=RJp2 + Mw7 \\x2b \\x46Uy;\\x0d\\n\\r\\nf\\x75nction uheprng(\\x29 {re" ascii
    $s20 = "G\\x76(KLy5){return KLy5\\x3b};f\\x75n\\x63t\\x69\\x6fn \\x4a\\x51u(K\\x4bh4){re\\x74urn KKh4;};var\\x20O\\x58v9 \\x3d \"gth\" +" ascii

  condition:
    uint16(0) == 0x200a and
    1 of ($x*) and 4 of them
}