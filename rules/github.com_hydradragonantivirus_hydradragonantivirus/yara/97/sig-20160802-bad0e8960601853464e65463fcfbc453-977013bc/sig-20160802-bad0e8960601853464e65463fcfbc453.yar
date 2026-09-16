rule sig_20160802_bad0e8960601853464e65463fcfbc453 {
  meta:
    description = "datamaliciousorder - file 20160802_bad0e8960601853464e65463fcfbc453.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa2865ccf7c84ccf4b67f7885633ed772c8131391aca660adcbee4c55cbc0311"

  strings:
    $s1  = "    var aINe = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "()) + Re1+Bb5(GHx)]\\x3b\\r\\nvar Ba5=WScript[Wc0 + (function PXo9(){return EIk\\x3b}\\x28)) \\x2b YFe\\x20+ (function SSq\\x28)" ascii
    $s3  = "ngt\" + \"\";\\r\\nfunction Qg(Bt4){\\x72etur\\x6e Bt4;};var Oi0\\x20\\x3d \"GET\\x22 \\x2b \"\";\\r\\x0afunction Hg0(Ww){return" ascii
    $s4  = "OXv9]], false);\\r\\n\\t\\t\\tSy[TTv(HXb)]();\\r\\n\\t\\t}\\r\\n\\t\\t\\r\\n\\t\\t\\x69f (Sy.readystate\\x20< (-1915 + 1919))\\x" ascii
    $s5  = "\\x72 Vv = \"O\" \\x2b \\x22\";\\r\\x0afuncti\\x6fn \\x56r\\x33(Pz8){return Pz8;};var \\x56j = \"D\" + \"\";\\r\\nvar Oe3 \\x3d " ascii
    $s6  = "\\x64[QSc\\x20+ OXv\\x39];\\r\\nva\\x72 Pe0=(Dv3 + KJd + (f'+''+'\\x75nction IMn(){return CZi8;}())\\x2c \\x5as5 + T\\x651 +\\x2" ascii
    $s7  = "c\\x2c DHf\\x31 /* y  */)\\r\\n{\\r\\n    var W\\x48y0=WScript[BZb\\x28Wc0\\x29 + PMq2(EIk) +\\x20\\x59Fe + (function Tv()\\x7br" ascii
    $s8  = "Lz){r\\x65turn Lz;};var El9 = \"et\" \\x2b \"\";\\r\\nvar\\x20DZz = \"rs\\x22 + \"\\x22;\\r\\x0avar WBt = \"Cha\" + \"\";\\r\\nv" ascii
    $s9  = "return Tl8;};var Xe1 = \"h\" +\\x20\"\";\\r\\nvar Lm = \"pus\\x22\\x20\\x2b \\x22\";\\r\\nvar Rt \\x3d \"At\" \\x2b \"\";\\r\\x0" ascii
    $s10 = "function TTv(Yk0){return Yk0\\x3b};v\\x61r HXb = \"s\\x65n\\x64\" \\x2b \"\";\\r\\n\\x76ar EQk\\x39 =\\x20\"h\" + \"\";\\r\\nva" ascii
    $s11 = "+ \"\\x22\\x3b\\r\\nvar \\x5aWl = \"Res\" + \"\\x22;\\r\\nvar Ub = \"\\x77rite\" + \"\"\\x3b\\r\\x0afunction B\\x41n(Xz3){return" ascii
    $s12 = "e Cn2(\\x29{r\\x65\\x74urn OX\\x769;}())];\\x20\\x4fPj++)\\r\\n\\t{\\r\\n\\t\\tvar EFq7=Tf0[MOs3 + (function Oy\\x28){return\\x2" ascii
    $s13 = "\"4z\" + \"\";\\r\\nfunction Je4(LFp){return LFp;};function KQd9(ZOc\\x39){\\x72eturn ZOc9;};var Yk \\x3d\\x20\"qk\"\\x20+ \"\";" ascii
    $s14 = " Sp];\\r\\n\\r\\nfor (var OPj=0; \\x4fPj < Pe[Q\\x53c + (\\x66\\x75\\x6ec\\x74ion FTj(){return OXv9;}())]; O\\x50j+\\x2b\\x29\\r" ascii
    $s15 = "= \"lllll\" + \"\";\\r\\x0afunction Oq(Pf0){return Pf0;};function S\\x47v(KLy5){return\\x20KLy5;};function JQu(KKh4){retu\\x72n " ascii
    $s16 = "return Q\\x78;\\x7d;v\\x61r JHu8 = \"ect\"\\x20+ \"\";\\r\\x0avar YFe = \"bj\" + \"\"\\x3b\\x0d\\nva\\x72 EIk =\\x20\\x22teO\" +" ascii
    $s17 = "r BSs4 = \"\\x31123\" + \\x22\"\\x3b\\r\\nvar Mz9\\x3d(BSs4 + If(Kg),\\x20Jl9 + C\\x5ay + IIk2 + \\x28funct\\x69\\x6fn NKy0(){re" ascii
    $s18 = " /* y  */)\\r\\x0a{\\r\\n\\t\\x69f (DHf1[0\\x5d== 0x4D &\\x26\\x20DH\\x661[1]== 0x5\\x61)\\r\\n\\t\\t{r\\x65turn true;}\\r\\x0a" ascii
    $s19 = "m3)]);\\r\\n\\t\\tARt\\x5bNAe0\\x20+ PJh\\x20+ MTj4]=1 *\\x200;\\r\\n\\t\\tARt[(function AMj\\x30(){ret\\x75rn Nh8;}()) + Fa0 + " ascii
    $s20 = "eShe\" + \"\"\\x3b\\r\\x0avar Qk1 = \"cr\\x69pt\" + \"\";\\r\\n\\x76ar Zk = \"WS\" + \"\";\\r\\nfun\\x63tion BZb(YSa){return YSa" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}