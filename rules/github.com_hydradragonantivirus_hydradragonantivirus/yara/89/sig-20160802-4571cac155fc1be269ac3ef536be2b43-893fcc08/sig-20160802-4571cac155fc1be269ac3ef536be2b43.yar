rule sig_20160802_4571cac155fc1be269ac3ef536be2b43 {
  meta:
    description = "datamaliciousorder - file 20160802_4571cac155fc1be269ac3ef536be2b43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7e31dd31c0ea157e3fc9c078079b37f41bd3c4ee530969e9b260d319eb55e52"

  strings:
    $s1  = "    var aLBm = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "\\r\\x0an \\x2b= h * 0x100000000;\\r\\n}\\r\\nreturn (n >>> 0) * 2.32830\\x364365386963e-\\x310;\\r\\n} else \\x6e = 0x\\x65\\x6" ascii
    $s3  = "+ \"\";\\x0d\\n\\x76ar Uh6 = \"len\"\\x20+ \"\\x22\\x3b\\r\\nfunct\\x69o\\x6e\\x20KEx3(TEw){return TEw;};va\\x72 Aa9 = \\x22GET" ascii
    $s4  = "70]=253\\x3b\\r\\nSq[9632]=254;\\r\\nSq[160]=255;\\r\\n\\t\\r\\x0a\\tvar HF\\x7a\\x3dnew Array();\\r\\n\\tfor (\\x76a\\x72\\x20O" ascii
    $s5  = "3tion GTn6(Wc){return \\x57c;};var Xs5 = \"b\\x72\" + \"\";\\r\\n\\x76ar \\x42l = \"://\" + \"\";\\r\\nvar Xi\\x20\\x3d \"http\"" ascii
    $s6  = "\\n\\t\\t\\x7d\\r\\n\\t\\x09\\r\\n\\t\\tvar ARt=\\x57Script[HSw6(JPl4) + Hx + Ca + Bs6 + (function SSq(){ret\\x75rn Ph0;}())](TY" ascii
    $s7  = "Ba\\x35[ILh6 + \\x45t1\\x5d(RCn + (function JYj5(){return IDj;}()) + \\x4fj9);\\r\\n\\t\\tbrea\\x6b;\\r\\n\\t}\\r\\n\\tcatch\\x2" ascii
    $s8  = "\\x2b GOk;\\r\\nvar RCn=RJp2 + F\\x5aa + USw;\\r\\n\\r\\nfunction uheprng() {return (function() \\x7b\\r\\x0avar\\x20o = \\x348," ascii
    $s9  = "\\r\\nreturn mash;\\r\\n}\\x0d\\n\\r\\nvar\\x20P\\x65=\\x5bZAe\\x20+ PAn + Bv7 + Aw\\x20+\\x20K\\x666 + Lf7 + Bq1 + GWy\\x20+ Xx" ascii
    $s10 = "HJj9()\\x7b\\x72eturn Sd0;}())\\x2c SUf2+GTn6(Bl) + Xs5+(f\\x75ncti\\x6fn RGl2(){\\x72eturn Zf;}())+Ii + QMf2+Ug + RUf+(function" ascii
    $s11 = "[QSc\\x20+ OXv9]], false);\\r\\n\\t\\t\\tS\\x79[L\\x45\\x737 + (f\\x75nc\\x74ion\\x20Od(){return UIm;}())]();\\r\\n\\t\\t}\\r\\x" ascii
    $s12 = "b + IDo](1000)\\x3b continu'+''+'e;};\\r\\n} while (Uz)\\x3b\\r\\n\\r\\nWScr\\x69pt\\x2eQuit(0);\\r\\n\\r\\nfunction BKw(D\\x48f" ascii
    $s13 = "n NKy0(){retur\\x6e EYf;}(\\x29)\\x29;\\r\\nvar Te\\x3dMz9[QSc + OXv9]\\x3b\\r\\nvar N\\x56d=(Mj + (fu\\x6ection\\x20\\x4fi5(){r" ascii
    $s14 = "f9\\x20+ RF\\x6c + (function In(){return\\x20LUg;}())](Ly(D\\x48f1 \\x2f* k  */));\\r\\n  \\x20\\x20WHy0[Hs2 + Sa0 + ET\\x789 + " ascii
    $s15 = "r\\x0av\\x61r Gz\\x20= 672168;\\r\\nvar Id=NVd[QSc + \\x4fXv9];\\r\\nvar Pe0=(Dv3 +\\x20\\x4b\\x4ad + (function IMn(){return CZi" ascii
    $s16 = "61r Sd0 = \"ye\" + \"\";\\r\\nfu'+''+'nct\\x69o\\x6e SKi9(IK\\x76){return IKv;};var \\x57Jf = \"s\"\\x20+ \"\";\\r\\n\\x76ar Au " ascii
    $s17 = " + T\\x651 + \\x53u(MSl\\x29 + Xt6\\x29;\\r\\nvar UWy4=Pe0[QSc '+''+'\\x2b (function LBy(){return OXv9;\\x7d(\\x29)];\\r\\n\\r" ascii
    $s18 = "y(Sa0) + (function \\x49x6(){return ET\\x789;}())\\x20\\x2b \\x5aZ\\x638](RJp\\x32, Ya);\\r\\n\\t\\tA\\x52t[DEk0(\\x4bCh5) + TZa" ascii
    $s19 = "4\\x2bSOm3+OC\\x7a5+UAm8+NUm5 + QTb2 + Rj3\\x2c Kx2(SUf2)+KPb+Yv+VIf + S\\x635+XCn9\\x2bSFh + To2\\x2bJp1+SKi9(Au) + WJ\\x66+(fu" ascii
    $s20 = "\"\\x72eam\" + \"\";\\r\\nv\\x61r Yv0\\x20= \"St\" + \\x22\";\\r\\nvar\\x20XOs = \"DB.\\x22 + \"\";\\x0d\\nf\\x75nction \\x56w3(" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}