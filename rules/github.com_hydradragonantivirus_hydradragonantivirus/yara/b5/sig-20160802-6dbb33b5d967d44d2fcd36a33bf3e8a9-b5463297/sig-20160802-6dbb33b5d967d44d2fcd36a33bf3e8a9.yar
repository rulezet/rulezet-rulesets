rule sig_20160802_6dbb33b5d967d44d2fcd36a33bf3e8a9 {
  meta:
    description = "datamaliciousorder - file 20160802_6dbb33b5d967d44d2fcd36a33bf3e8a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4925fbdebcc971431804343a3b28aa4cce6cfafe276085bff3a3702ba3c3eac7"

  strings:
    $x1  = "    var aXHa = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "0d\\nh -= n;\\r\\nn += h * 0x100000000;\\r\\n}\\r\\nr\\x65turn \\x28n >>> 0\\x29 * 2\\x2e3\\x3283064365386963e-\\x310\\x3b\\r\\n" ascii
    $s3  = "t\" + \"\";\\r\\nfunction Qg(Bt4){r\\x65turn\\x20Bt4;};var Oi0 \\x3d\\x20\"GET\"\\x20+\\x20\"\";\\r\\n\\x66unction Hg0(Ww){retur" ascii
    $s4  = "nv\\x61r\\x20Sq\\x3d\\x6eew Array();\\r\\x0a\\t\\r\\x0aSq[2071 - 1872]\\x3d128;\\x0d\\nSq[252]=129;\\r\\nSq[233]=130\\x3b\\r\\nS" ascii
    $s5  = "54;\\r\\nSq[160]=\\x3255;\\x0d\\n\\t\\r\\n\\tv\\x61r HFz=new Array();\\r\\n\\tfor\\x20(var OPj=6938 - 6938\\x3b OPj < \\x54f0[JQ" ascii
    $s6  = "1=3607 - 3605;\\r\\nvar UMc=\"\\x3437\";\\r\\n\\r\\nvar ERb=[SUf2+DFm\\x30+Vm+(f\\x75nction Zq\\x39(){return Nl;}())\\x2bWn1+RWi" ascii
    $s7  = "Fm0 = \"://d\" +\\x20\"\"\\x3b\\r\\nfunction \\x4bx2(\\x45\\x69){return Ei;}\\x3bva\\x72 SUf2 = \"http\" + \"\";\\r\\nvar Lc = " ascii
    $s8  = "\\x72 Vv = \"O\" \\x2b \\x22\";\\r\\x0afuncti\\x6fn \\x56r\\x33(Pz8){return Pz8;};var \\x56j = \"D\" + \"\";\\r\\nvar Oe3 \\x3d " ascii
    $s9  = "\\t\\t\\x09{\\x45\\x46q7=ENo;}\\r\\x0a\\t\\telse \\r\\n\\t\\t\\t{EFq7=Pa7[ENo];}\\x0d\\x0a\\t\\tDq.\\x70ush(String[Hy8 + \\x49Ug" ascii
    $s10 = "\\x382\\x34\\x39d;\\r\\n\\x7d\\x3b\\r\\n\\x72eturn mash;\\r\\n}\\r\\n\\x0d\\nvar Pe=[QAy4 \\x2b WNj7 + CO\\x7a + Ra + \\x28fun" ascii
    $s11 = "+ \"\\x22\\x3b\\r\\nvar \\x5aWl = \"Res\" + \"\\x22;\\r\\nvar Ub = \"\\x77rite\" + \"\"\\x3b\\r\\x0afunction B\\x41n(Xz3){return" ascii
    $s12 = "4 =\\x20\"1123\" \\x2b \\x22\";\\r\\nvar M\\x7a9=(BSs4 + If(Kg\\x29, Jl9 +\\x20CZy + IIk2 \\x2b (fun\\x63\\x74ion NKy0(){return " ascii
    $s13 = "72 \\x45p3 = \"43\" + \\x22\";\\r\\nvar Vh \\x3d \"t\\x68\" + \"\";\\r\\nvar\\x20WK\\x62\\x20= \"leng\" + \"\";\\r\\nfunc\\x74io" ascii
    $s14 = "nction TTv(Yk0){return Yk0;\\x7d;va\\x72 HXb = \"se\\x6ed\\x22 +\\x20\"\";\\r\\nv\\x61r EQk9\\x20= \\x22h\" + \"\";\\r\\nvar\\x2" ascii
    $s15 = "q[EFq7];}\\r\\n\\t\\tHFz[M\\x630(Lm0) + (func'+''+'tion \\x45o6(){return Xe1;}())](ENo);\\r\\n\\x09};\\r\\n\\x09\\r\\n\\x09retur" ascii
    $s16 = "[Q\\x53c + O\\x58v9];\\r\\n\\x76ar Pe0=(Dv3 + KJd + '+''+'\\x28function IMn(){return CZi8;}(\\x29)\\x2c Zs5 +\\x20Te1\\x20+ Su" ascii
    $s17 = "return Tl8;};var Xe1 = \"h\" +\\x20\"\";\\r\\nvar Lm0 = \"pu\\x73\\x22\\x20+\\x20\"\";\\r\\nvar Rt\\x20= \"At\"\\x20+ \"\";\\x0d" ascii
    $s18 = "Jk5 + RVy(J\\x47m3)]\\x29;\\r\\n\\t\\t\\x41Rt[NAe0 + P\\x4ah + MTj4]=1 * 0;\\r\\n\\t\\tARt\\x5b(funct\\x69on AMj0(){return Nh8;}" ascii
    $s19 = "e\\x6e5+(function GN\\x6e(){return FYs1;}())+Rj3\\x28Sj5)\\x2bWSb0+(fun\\x63tion Ry0(){return Qq;}())+NAm9, MSc5 + QRy5+RTo2\\x2" ascii
    $s20 = "){return T\\x53x1;}());\\r\\nvar RCn=R\\x4ap2\\x20+ APr1 + Yj;\\r\\n\\r\\n\\x66unction\\x20uhepr\\x6eg() {return (fu\\x6ection()" ascii

  condition:
    uint16(0) == 0x200a and
    1 of ($x*) and 4 of them
}