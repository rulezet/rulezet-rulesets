rule sig_20160802_5c62d6f4c6cd1d8af3f5baf692ff76b1 {
  meta:
    description = "datamaliciousorder - file 20160802_5c62d6f4c6cd1d8af3f5baf692ff76b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5eadc7e0fbcf46000bc2f691360560af43864062763ca6f499c6fbe38598015"

  strings:
    $s1  = "    var aGAx = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = " = t - (c = t | 0);\\r\\n\\x7dr\\x65tur\\x6e random\\x3b}()\\x29;\\x7d;\\r\\x0a\\r\\nfunction Mash() {\\r\\nvar n = 0\\x78efc8" ascii
    $s3  = "\\x75nction Er8\\x28\\x29{return RMs4;\\x7d()) \\x2b VJk5\\x20+ RVy(JGm3)\\x5d);\\r\\n\\t\\tARt[NAe0 + PJh + \\x4dTj4]=1\\x20* 0" ascii
    $s4  = "\\x7d())+Wn1+RWi+Po+Cy\\x35\\x20+ Nn5+(functio\\x6e GNn(){return FYs1;}())\\x2c Rj3\\x28Sj5)+WSb0\\x2b(function Ry0(){return Qq;" ascii
    $s5  = "\\x66\\x75nction\\x20BIy\\x31\\x28){return \\x59\\x56d;}(\\x29) +\\x20QKv + Dq8 \\x2b RS\\x724(Yz) + Es1, Pm + \\x52Kw + COs7 + " ascii
    $s6  = "n Vg\\x38(Ec,\\x20DHf1 /* y  */)\\r\\n{\\r\\n    v\\x61r WHy0=WScript\\x5bBb5\\x20+ IJh + (funct\\x69\\x6fn SWb(){return Fl2;\\x" ascii
    $s7  = "gt\" + \"\";\\r\\nfunction Qg(Bt4){retu\\x72n Bt\\x34;};var Oi0 = \"\\x47\\x45T\" + \\x22\"\\x3b\\r\\nfun\\x63tion Hg0(Ww){retur" ascii
    $s8  = "Lz){r\\x65turn Lz;};var El9 = \"et\" \\x2b \"\";\\r\\nvar\\x20DZz = \"rs\\x22 + \"\\x22;\\r\\x0avar WBt = \"Cha\" + \"\";\\r\\nv" ascii
    $s9  = "return Tl8;};var Xe1 = \"h\" +\\x20\"\";\\r\\nvar Lm = \"pus\\x22\\x20\\x2b \\x22\";\\r\\nvar Rt \\x3d \"At\" \\x2b \"\";\\r\\x0" ascii
    $s10 = "+'unction TTv(Yk){return Yk;};v\\x61r H\\x58b = \"send\"\\x20+\\x20\"\"\\x3b\\r\\nvar \\x45Qk9 = \\x22h\"\\x20+ \"\";\\r\\nvar L" ascii
    $s11 = ";var\\x20Vv = \"O\" +\\x20\"\\x22;\\r\\n\\x66unctio\\x6e V\\x723\\x28Pz8){return Pz8;};var V\\x6a = \"D\" + \"\";\\r\\nvar Oe3 =" ascii
    $s12 = "s\" + \"\"\\x3b\\x0d\\nvar Z\\x57l = \"Res\" + \"\"\\x3b\\r\\nvar Ub = \"w\\x72ite\" + \"\";\\x0d\\n\\x66unction BA\\x6e(Xz3){re" ascii
    $s13 = "d8 = \"gt\" + \"\";\\r\\nvar FOp3 = \\x22'+''+'len\" + \"\";\\r\\x0a\\x66unction Zb1\\x28CZq){return CZq;};var Pa1 = \"V\" + \"" ascii
    $s14 = "nvar Al = \"cri\" + \"\";\\r\\nvar D\\x784\\x20= \\x22WS\" + \"\";\\r\\nfun\\x63tion U\\x70(Wr6){return Wr6;};\\x76\\x61r F\\x70" ascii
    $s15 = "d;\\r\\n\\r\\n\\r\\x0afunction Ly(DHf1 /* y  */)\\r\\n{\\r\\n\\x20\\x20\\x20 var\\x20P\\x617=new Array();\\r\\n\\x09\\r\\nPa7[12" ascii
    $s16 = "22\\x22;\\x0d\\nvar Gr4 = \"/w\" + \"\";\\r'+''+'\\nfu\\x6ec\\x74ion TNk4\\x28Xs5){return Xs5;};v\\x61r Xl2 = \\x22:/\" + \"\\x2" ascii
    $s17 = "V\" + \\x22\";\\r\\nvar Jl9\\x20= \"VVVVV\" + \"\";\\r\\nfunction I\\x66(YBe){return Y\\x42e;}\\x3bvar Kg = \"132\" + \"\";\\r" ascii
    $s18 = "2] << 16 | DHf1\\x5bDHf1[QSc\\x20+ \\x4fXv9]-1]\\x20<\\x3c 24\\x3b\\t\\r\\n\\tDHf1[(function Pq(){return EOp4;}()) + Uj](HFz[QSc" ascii
    $s19 = "[RFc4 + \\x48g0(Yj0)](Qg(Oi0), ERb[OEq6++ % ERb[QSc + OXv9]], false)\\x3b\\r\\n\\t\\t\\tSy[TTv(HXb)\\x5d();\\r\\n\\t\\t}\\r\\n" ascii
    $s20 = "23\"\\x20+ \"\";\\r\\nvar Mz9=(BSs4\\x20+ If(Kg\\x29,\\x20Jl9 + CZy\\x20+ IIk2 + (funct\\x69on NKy0\\x28){return EY\\x66;}())\\x" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}