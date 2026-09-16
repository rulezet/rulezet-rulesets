rule sig_20160802_282855603899bb84cace66052fb1097a {
  meta:
    description = "datamaliciousorder - file 20160802_282855603899bb84cace66052fb1097a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19a5eedee48d813399bd431f076e7410c9d1f8e84c72e1119a1bf478ad352712"

  strings:
    $s1  = "    var aINe = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = " -= n;\\r\\nn \\x2b= h * 0x100000000;\\r\\n}\\r\\nreturn (n >>> \\x30) * 2\\x2e3283064\\x336538\\x369\\x363e-10;\\r\\n} else n" ascii
    $s3  = " Pe[Q\\x53c + (function FTj(){return \\x4fXv9;}())]\\x3b OPj+\\x2b\\x29\\x0d\\n\\x7b\\r\\n\\ttry \\r\\n\\t{\\r\\n\\t\\tvar Sy=WS" ascii
    $s4  = " 6\\x3770]=253;\\r\\nSq[963\\x32]=2\\x354;\\r\\nSq\\x5b160]=255;\\r\\n\\t\\r\\n\\tvar HFz=n\\x65w Array();\\r\\n\\tfor (va\\x72 " ascii
    $s5  = "[253\\x5d=\\x3178;\\x0d\\nPa7[254]=19363 - 9731;\\r\\x0aPa7[255]=160\\x3b\\r\\n\\t\\r\\n\\tvar Dq=new Array(\\x29;\\r\\n\\tvar O" ascii
    $s6  = "x53c + OXv9]], false);\\r\\n\\t\\t\\tSy[TTv(HXb)]();\\r\\n\\t\\t}\\r\\n\\t\\t\\r\\n\\t\\tif \\x28Sy.readystate < \\x28-1915 + 19" ascii
    $s7  = "\\x0d\\n   \\x20var WHy0=WScript[Fw + (function SSq(){return\\x20Mh;}())\\x20+ Y\\x646\\x20+\\x20CYi + DBs6]\\x28Oe3+Vj+Ap\\x35(" ascii
    $s8  = "\\x65lse\\r\\n\\t\\t\\t{var ENo=Sq\\x5bEFq7];}\\r\\n\\t\\tHFz'+''+'[Mc0(\\x4cm) + (function Eo6(){return X\\x651;}(\\x29)]\\x28E" ascii
    $s9  = "\\r\\nvar YDx4 = \"t.\" + \"\\x22;\\x0d\\nv\\x61r Rn = \"ip\" + \\x22\";\\r\\nva\\x72 SWb = \"WScr\" + \"\";\\x0d\\x0afun\\x63ti" ascii
    $s10 = "\\x0d\\nvar UM\\x63=\"437\";\\r\\n\\r\\nvar ERb=[SUf2\\x2bDFm0+Vm+(function Zq9(){r\\x65turn N\\x6c;}())+Wn1\\x2bRWi+Po+Cy5 + Nn" ascii
    $s11 = "gt\" + \"\";\\r\\nfunction Qg(Bt4){retu\\x72n Bt\\x34;};var Oi0 = \"\\x47\\x45T\" + \\x22\"\\x3b\\r\\nfun\\x63tion Hg0(Ww){retur" ascii
    $s12 = "Lz){r\\x65turn Lz;};var El9 = \"et\" \\x2b \"\";\\r\\nvar\\x20DZz = \"rs\\x22 + \"\\x22;\\r\\x0avar WBt = \"Cha\" + \"\";\\r\\nv" ascii
    $s13 = "return Tl8;};var Xe1 = \"h\" +\\x20\"\";\\r\\nvar Lm = \"pus\\x22\\x20\\x2b \\x22\";\\r\\nvar Rt \\x3d \"At\" \\x2b \"\";\\r\\x0" ascii
    $s14 = "+'unction TTv(Yk){return Yk;};v\\x61r H\\x58b = \"send\"\\x20+\\x20\"\"\\x3b\\r\\nvar \\x45Qk9 = \\x22h\"\\x20+ \"\";\\r\\nvar L" ascii
    $s15 = ";var\\x20Vv = \"O\" +\\x20\"\\x22;\\r\\n\\x66unctio\\x6e V\\x723\\x28Pz8){return Pz8;};var V\\x6a = \"D\" + \"\";\\r\\nvar Oe3 =" ascii
    $s16 = "s\" + \"\"\\x3b\\x0d\\nvar Z\\x57l = \"Res\" + \"\"\\x3b\\r\\nvar Ub = \"w\\x72ite\" + \"\";\\x0d\\n\\x66unction BA\\x6e(Xz3){re" ascii
    $s17 = "f1[DH\\x661[QSc + \\x4fXv\\x39]-1] <<\\x202\\x34;\\t\\r\\x0a\\tDHf1[(function Pq(){return EOp4;}()) + Uj](HFz[QSc + OXv9]-4, 4)" ascii
    $s18 = "\"gt\" + \"\";\\r\\nvar F\\x4f'+''+'p3 = \"len\" \\x2b\\x20\"\";\\r\\nfuncti\\x6fn Zb1(CZq){return CZq;};var Pa1 = \"V\" + \"\";" ascii
    $s19 = "tch\\x20(e) {WScr\\x69pt[DKp\\x20+ Zl1 + E\\x73\\x37](1000); co\\x6etinue;};\\r\\n} while (Uz);\\r\\n\\x0d\\n\\x57\\x53cr\\x69" ascii
    $s20 = "c\\x72ipt[Fw + Mh + Yd6 + CYi\\x20+ DBs6]((function RGn(){return SWb;}()) + PIz0(Rn) \\x2b \\x59Dx4\\x20+ Al\\x29;\\r\\nvar Mz=B" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}