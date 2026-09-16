rule sig_20160802_2cdeedb42ff52c776d14b7b89157c204 {
  meta:
    description = "datamaliciousorder - file 20160802_2cdeedb42ff52c776d14b7b89157c204.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be67703103ce6244f6429c2c9d8f850bdc254e7437cd0a3a51097ae8ded203f4"

  strings:
    $s1  = "    var aCj3 = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "2Uf+Cp + IHt+(fu\\x6ection W\\x636(){return HPu9;}\\x28\\x29\\x29+Re1 \\x2b CNe\\x32+Bb\\x35(Hx)+Ni1 + EIk+Eq8 + KEy7+Qy\\x33 + " ascii
    $s3  = "r\\n};\\r\\n\\r\\n\\r\\n\\x66unction Vg\\x38(Ec,\\x20DHf\\x31 /* s  \\x2a/)\\r\\n{\\r\\n    var WHy0=WScript[(fu\\x6ection PMw7" ascii
    $s4  = "\\x28\\x45f){r\\x65turn Ef;};va\\x72 JYk\\x20=\\x20\"c\\x6cose\"\\x20+ \"\";\\r\\x0afuncti\\x6f\\x6e Ss(Gh7){return G\\x68\\x37;" ascii
    $s5  = "\\x52\" + \"\";\\r\\n\\x76a\\x72 Cc1 = \"h9\" +\\x20\"\";\\r\\nvar KC\\x68 = \"9YNsj\" + \"\";\\r\\nfunct\\x69on VHo(Pd9){return" ascii
    $s6  = "\" \\x2b \"\";\\r\\nvar Tw = \"\\x52e\" + \"\"\\x3b\\r\\nf\\x75nc\\x74ion AJ\\x614\\x28Xj6){return Xj6;};funct\\x69on Yc9(G\\x6a" ascii
    $s7  = "n\" + \"\";\\r\\nfuncti\\x6fn WQh(J\\x6d){return Jm;};\\x66unc\\x74\\x69o\\x6e VWu1\\x28SPi8){r\\x65turn\\x20SPi8;};function Vz6" ascii
    $s8  = "e\\x74urn\\x20(n >\\x3e> 0)\\x20* 2.32830\\x364\\x3365386963e-10\\x3b\\r\\n} else n = 0xefc8249d\\x3b\\r\\n\\x7d\\x3b\\r\\nretu" ascii
    $s9  = "return WSb0\\x3b}()) +\\x20IOg6+ZV\\x653 + MS\\x63\\x35+X\\x43n9\\x2b\\x53Fh + \\x54o2+Jp1+(f\\x75nction WJf(){return Ja;}(\\x29" ascii
    $s10 = "Go(UR\\x799)+Xz3 + Zc8\\x20+ Tn + BXy);\\r\\x0a\\t\\tARt[LWi5]();\\r\\n\\t\\tARt[Mb0 + (\\x66unction '+''+'Wh1(){return Aa6;}\\x" ascii
    $s11 = "x09{\\x0d\\n\\x09\\t\\t\\tOEq\\x36=0;\\r\\n\\t\\t\\t\\tWS\\x63ript[Kp\\x37 + (function Wt6(){\\x72eturn GFr;\\x7d\\x28)) + Gi2](" ascii
    $s12 = "nvar Ep3 = \"43\" \\x2b'+''+' \"\";\\r\\nvar V\\x68\\x20= \"th\" + \"\"\\x3b\\r\\nvar WKb = \"leng\" + \"\";\\r\\nfunction Su(SH" ascii
    $s13 = "\"Cre\" + \"\";\\r\\nfunction BZb(YSa){return YSa;};function PMq2(Qx){return \\x51x;\\x7d;var Kh = \"4\" + \"\";\\r\\x0a\\x76ar " ascii
    $s14 = "l\\x65\\x22 + \"\";\\x0d\\nvar NMx = \"ve\\x54o\" + \"\";\\r\\nvar\\x20YQo = \"Sa\"\\x20+\\x20\"\";\\r\\nfunct\\x69on IDj(Oj9){r" ascii
    $s15 = "v+Aq +\\x20HJj9\\x2bQu+DXs5 + Lq3, (fun\\x63tion RGl2(){return \\x45d;\\x7d()) + (function \\x49i(){ret\\x75rn Zf\\x3b}())+Mf2+V" ascii
    $s16 = "[QSc + (fu\\x6ectio\\x6e LBy(\\x29{return OXv9;\\x7d())];\\r\\n\\r\\nvar\\x20GRx5=1;\\r\\nvar DA\\x65=2;\\r\\x0ava\\x72 Ya=3607 " ascii
    $s17 = "l\" + \"\";\\r\\nv\\x61r\\x20Jl9 \\x3d \"lllll\" + \"\";\\r\\nfunction If(\\x59Be){return YBe;};var \\x4b\\x67\\x20= \"132\" + " ascii
    $s18 = "+ \"\";\\r\\nvar EIk = '+''+'\"i\"\\x20+\\x20\"\";\\r\\nvar\\x20Ni1 = \"-onl\" + \"\";\\r\\x0afunction\\x20Bb5(IJh\\x29{return I" ascii
    $s19 = "unction Zq9(){retu\\x72n Nl;}())+Wn1+RWi+Po+Cy\\x35 + Nn5+(function GNn(){return FYs1;}())+QTb2, SUy3+\\x28f\\x75nct\\x69on R\\x" ascii
    $s20 = "t\\t}\\r\\n\\x09\\t\\tSy[LWi5](\\x4cHe4, ERb[OEq6++ % ERb[Q\\x53c + OX\\x769]], false);\\r\\n\\t\\t\\tSy[(function L\\x694(){ret" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}