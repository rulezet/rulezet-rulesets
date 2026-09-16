rule sig_20160802_bbcad47c286f2cde8732b9616871888a {
  meta:
    description = "datamaliciousorder - file 20160802_bbcad47c286f2cde8732b9616871888a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76d5ee227ee4357bb238ed3c01586cd40535c4e759adcf5845545fbff57fa4bf"

  strings:
    $s1  = "    var aJCm8 = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51" ascii
    $s2  = "ngt\" + \"\";\\r\\nfunction Qg(Bt4){re\\x74urn \\x42t4;};var Oi0 =\\x20\\x22GET\" \\x2b \\x22\";\\r\\nf\\x75nction Hg0(Ww){retur" ascii
    $s3  = "\\x0d\\nPa\\x37[25\\x34]=\\x319363 - 973\\x31\\x3b\\r\\nPa7[255]=16\\x30;\\r\\n\\t\\x0d\\n\\tvar Dq=\\x6eew Array();\\x0d\\n\\tv" ascii
    $s4  = "[p] + c * 2.32830643\\x36538\\x36963e-10;\\r\\nreturn s[p] =\\x20t \\x2d (c = t | 0);\\r\\n}return ra\\x6ed\\x6fm;}());};\\r\\n" ascii
    $s5  = "72 DAe=2;\\x0d\\nvar Ya=3607 - 3605;\\r\\nva\\x72 UMc=\"437\";\\r\\n\\r\\nvar ERb=[S\\x55f2+DFm\\x30+Vm+(func\\x74ion Zq9(){retu" ascii
    $s6  = "\\nfunction TTv(Yk){return Yk;}\\x3bvar\\x20HXb = \"sen\\x64\"\\x20+ \\x22\";\\r\\nva\\x72 EQk9 \\x3d \"\\x68\" + \"\";\\r\\nvar" ascii
    $s7  = "\\x75rn Wr6;}()) + (function \\x45Hf(){return SK\\x75;}(\\x29) + PXo9](Oe3+\\x56\\x723(Vj)+(function Gk(\\x29{ret\\x75rn Vv;\\x7" ascii
    $s8  = "\\x651 + Su\\x28MSl) +\\x20Xt6);\\r\\nv\\x61r UWy4=Pe0[QSc + \\x28function LBy(){return OXv9;}())];\\r\\n\\r\\nvar \\x47Rx\\x35=" ascii
    $s9  = "{return Tl8;};var Xe1 = \"h\" +\\x20\"\";\\r\\nvar Lm = \"pus\\x22\\x20\\x2b \\x22\";\\r\\nvar Rt \\x3d \"At\" \\x2b \"\";\\r\\x" ascii
    $s10 = "Shel\\x22 + \"\";\\r\\nv\\x61r\\x20Yz4 = \"ipt\" +\\x20\"\";\\r\\nvar Me\\x20= \"WScr\" + \"\";\\r\\nfunctio\\x6e BZb(YSa){retur" ascii
    $s11 = " functio\\x6e( ra\\x6ege ) \\x7b\\r\\nret\\x75rn Math.floo\\x72(range * \\x28rawprng() \\x2b (ra\\x77\\x70rng() * 0x2\\x30\\x300" ascii
    $s12 = "Es\\x31, P\\x6d\\x20+ RKw + C\\x4f\\x737 + \\x52u +\\x20Sp];\\r\\n\\r\\nfo\\x72 (v\\x61r OPj=0; OPj < Pe[\\x51Sc + (function FTj" ascii
    $s13 = " P\\x721 + Yj;\\r\\n\\r\\nfunction\\x20uheprng() {return (\\x66un\\x63tion() {\\r\\nvar o \\x3d 48, c \\x3d 1, p\\x20= o, s = ne" ascii
    $s14 = "turn \\x4e\\x688;}()) + Fa0 \\x2b ASj\\x5d(RJp2\\x2c Ya);\\r\\n\\t\\tAR\\x74[HIk]();\\r\\n\\t\\r\\n\\t\\tvar HFz=\\x4bTb8 /*\\x2" ascii
    $s15 = "x36+JZq + Hg];\\r\\nvar Ba5=WS\\x63ript[Ym5 + (function SSq(){return Wr6;}()) + SKu + \\x50X\\x6f9](\\x4de + \\x59z4 + Kr6 + Bz)" ascii
    $s16 = "32\" + \"\";\\r\\nvar\\x20BSs4 = \\x221\\x3123\" + \"\";\\x0d\\nvar Mz9=(BSs4 \\x2b If(Kg)\\x2c Jl9 + CZy \\x2b IIk2\\x20\\x2b (" ascii
    $s17 = "};v\\x61r Vv = \"O\"\\x20+\\x20\"\";\\x0d\\nfunct\\x69on\\x20V\\x723(Pz8){return Pz8;};var\\x20Vj = \"D\" + \"\";\\r\\nvar Oe3" ascii
    $s18 = " | DHf1[DHf1[QSc + OXv\\x39]-1] << 2\\x34;\\t\\r\\n\\tDHf1[(funct\\x69on Pq\\x28){return EOp4\\x3b}()) + Uj](HFz[QSc + O\\x58v9]" ascii
    $s19 = ";\\r\\nvar La6 = \"bs\" '+''+'+ \"\\x22;\\x0d\\nfunctio\\x6e GTn6(Wc){return Wc\\x3b};var Xs\\x35 = \"fa\"\\x20+ \"\";\\r\\nvar " ascii
    $s20 = "\"\";\\r\\nvar Mj = \"llll\\x6c\" + \"\";\\r\\nfunction Oq(Pf0){return Pf0;};f\\x75nction SGv(KLy\\x35){return KLy5;};function J" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}