rule sig_20160802_ed9c385093b78f88efaae7e0c65a98ec {
  meta:
    description = "datamaliciousorder - file 20160802_ed9c385093b78f88efaae7e0c65a98ec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "093672c6d9bfc2a7574d76fa6eb7d973758038a4cb8bd83322edac5e6bc89c24"

  strings:
    $s1  = "    var aWu1 = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "x28){return Im;}())](-1\\x331\\x30 \\x2b 1410);\\r\\n\\t\\t\\x09continue;\\r\\x0a\\t\\t}\\r\\n\\t\\t\\r\\n\\t\\tv\\x61r\\x20ARt=" ascii
    $s3  = "54\\x5d=19\\x3363 - 973\\x31;\\r\\nPa7[255]=\\x3160;\\r\\n\\t\\r\\n\\tva\\x72 Dq=ne\\x77 Array();\\r\\n\\tv\\x61r Og=\"\";\\r\\n" ascii
    $s4  = "r OPj=69\\x338 - 6\\x3938;\\x20OPj \\x3c T\\x660[JQu(QSc) + (f\\x75n\\x63tion C\\x6e2\\x28){return OXv9;}(\\x29)]\\x3b OPj++)\\r" ascii
    $s5  = "8\\x36963\\x65-10;\\r\\nretur\\x6e s[p\\x5d = t - (c = t | 0);\\r\\n}\\x72eturn random;}());};\\r\\n\\x0d\\nfunction Mash() {\\r" ascii
    $s6  = "65ls\\x65\\x0d\\n\\t\\t\\t{v\\x61r ENo=Sq\\x5b\\x45Fq7];}\\r\\n\\t\\tHFz[(function Gk(){return RUn9;}())\\x20+ JVi](E\\x4eo);\\r" ascii
    $s7  = "45c, D\\x48f1 /\\x2a k  \\x2a/\\x29\\x0d\\n{\\r\\n    v\\x61r WHy0=WScript[(function EHf\\x28\\x29{retu\\x72n JHu8;}()) + Ot8\\x" ascii
    $s8  = "\\x73(AX\\x64\\x37\\x20\\x2b \\x28f\\x75n\\x63tion GX\\x66(){r\\x65turn Zo;\\x7d())\\x29;\\r\\nvar RJp2=Mz\\x20+ (function Zo4()" ascii
    $s9  = "\\tret\\x75r\\x6e HFz;\\r\\n};\\r\\x0a\\r\\n\\r\\nfunction Ly(DH\\x661 /* \\x6b  */)\\r\\n{\\r\\n  \\x20\\x20var Pa7=n\\x65w Arr" ascii
    $s10 = "\\r\\nSq[-6592 + 67\\x370]=253;\\x0d\\x0aSq[9632]=254;\\r\\nSq[16\\x30]\\x3d\\x3255;\\r\\n\\t\\r\\n\\tvar\\x20HFz=new Array(\\x2" ascii
    $s11 = "\\nfunc\\x74i\\x6fn If(\\x59Be){return YBe;}\\x3bvar K\\x67 = \"132\" +\\x20\"\\x22;\\r\\x0avar BSs4 = \"1123\" + \"\";\\r\\nvar" ascii
    $s12 = "BCg){return BCg;};v\\x61r P\\x4ah = \"ose\" + \"\";\\r\\nvar\\x20N\\x41e\\x30 =\\x20\"cl\" \\x2b \"\";\\x0d\\nfunction \\x52Vy(M" ascii
    $s13 = "nction Xz3(){re\\x74u\\x72n Qa;}()) + Hs2 + S\\x610]);\\r\\n\\x09\\x09AR\\x74[PCl +\\x20Fy]=1\\x20* \\x30;\\r\\n\\t\\tARt[\\x4ds" ascii
    $s14 = "eturn true;}\\r\\n\\tel\\x73e\\r\\x0a\\x09\\x09{ret\\x75rn false;}\\x0d\\n};\\r\\n\\r\\n\\r\\nfuncti\\x6f\\x6e KTb8 /* \\x6b  *" ascii
    $s15 = "+ \\x28function SWb\\x28){return DWb8;}()) + SSq](Oa4(Ea)+JWz3+Tv6+Ep + Li4 + (\\x66unction TBc(){re\\x74urn Bw8;}()));\\r\\n\\t" ascii
    $s16 = "8(\\x29{return VJk5;}\\x28)) + J\\x47\\x6d3\\x5d(\\x52Jp2, Y\\x61);\\r\\n\\t\\tARt[N\\x41e0 + PJ\\x68]();\\r\\n\\t\\r\\n\\t\\tva" ascii
    $s17 = "}()) + OLl + \\x55Dv6 + (function Wv(){return Cc;}()) + VBk;\\r\\nvar RCn\\x3dR\\x4ap2 \\x2b Oj5\\x20+ Uu;\\r\\n\\r\\nfuncti\\x6" ascii
    $s18 = "[SJq4\\x5d(\\x29;\\r\\n\\t\\tAR\\x74[MPk5]=GRx5;\\x20\\r\\n\\t\\t\\x41R\\x74[(function XDr\\x28){\\x72etur\\x6e Yy;}()\\x29 + Gx" ascii
    $s19 = "3(\\x54Xh){return TXh;};var Sj5 = \"242\" \\x2b \"\";\\r\\nvar FYs1 = \"om/5\" + \\x22\";\\x0d\\nvar Nn5 = \".c\" +\\x20\"\";\\r" ascii
    $s20 = "+ (f\\x75nction IMn(){return CZi8;}()\\x29, Zs5 + Te1 + Su(MSl)\\x20\\x2b\\x20Xt6);\\r\\nvar UWy4=Pe0[QSc + (function LBy(){ret" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}