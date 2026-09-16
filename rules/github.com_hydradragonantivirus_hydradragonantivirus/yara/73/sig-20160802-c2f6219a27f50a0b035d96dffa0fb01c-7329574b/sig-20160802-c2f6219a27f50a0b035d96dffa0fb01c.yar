rule sig_20160802_c2f6219a27f50a0b035d96dffa0fb01c {
  meta:
    description = "datamaliciousorder - file 20160802_c2f6219a27f50a0b035d96dffa0fb01c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f04416c380a6104b0b383de1d744ed16a36a922b261a31c5c0bd0cc235872d9"

  strings:
    $x1  = "    var aMk = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x7" ascii
    $s2  = "o\\x6etinue;};'+''+'\\r\\n} while (Uz);\\r\\n\\r\\x0aWScript.\\x51ui\\x74(0);\\r\\n\\r\\nfunction BKw(DHf1 \\x2f* k  */)\\x0d\\n" ascii
    $s3  = "c + (function F\\x54j\\x28\\x29{ret\\x75\\x72n \\x4fXv9;}())]; OPj++\\x29\\r\\n{\\r\\n\\ttry \\r\\n\\t{\\x0d\\n\\t\\tvar Sy=\\x5" ascii
    $s4  = "'+'unction Tf2(Hg0){return Hg0;}\\x3bvar\\x20FFm = \"GET\\x22 \\x2b \"\\x22;\\r\\nvar\\x20Hp0 = \\x22n\"\\x20+ \"\";\\r\\nvar ES" ascii
    $s5  = "r\\nvar UWy4=\\x50e\\x30[QSc\\x20+ (function LBy(){return OXv\\x39;}())];\\r\\n\\r\\nvar GRx5=1\\x3b\\x0d\\x0avar DAe=2;\\r\\nva" ascii
    $s6  = "4365386963e-10\\x3b\\r\\nr\\x65turn s[p] =\\x20t - \\x28c = t | 0);\\r\\n}return r\\x61ndom;}());};\\r\\n\\r\\nfuncti\\x6fn Mash" ascii
    $s7  = "rip\\x74[Eq\\x38 + KEy7 + Jy\\x37 + LXw](Oa4(Ea)+JWz3+Tv6+Ep + Li4 + (function TBc(){ret\\x75rn Bw8;}()));\\r\\n\\t\\x09ARt[ESh " ascii
    $s8  = "un\\x63tion Gi2(){return Mf;}(\\x29) \\x2b\\x20MVd1](\\x29;\\r\\x0a\\t\\t}\\x0d\\n\\t\\t\\r\\n\\t\\tif (Sy.readystate < (-1\\x39" ascii
    $s9  = "\\x33(){return Qa;}()) \\x2b \\x48s2 + Sa0]);\\r\\n\\t\\tARt[\\x50Cl + F\\x79\\x5d=1\\x20* 0;\\r\\n\\x09\\tARt[\\x4ds4\\x20+ (fu" ascii
    $s10 = "\\x6a++)\\r\\n\\t{\\r\\x0a\\t\\t\\x52Et2=(RE\\x742\\x20+ D\\x48f1[OPj]) % 0x100000000;\\r\\n\\t};\\r\\n\\tif (REt2 != Cm) {retur" ascii
    $s11 = "\\x22;\\x0d\\nvar Un = \"edam\" + \"\";'+''+'\\r\\nf\\x75n\\x63tion RTo\\x32(Xh1){return Xh1;};\\x76ar Lr8 =\\x20\"noarr\"\\x20+" ascii
    $s12 = "P\\x43\\x6c = \"\\x70osit\" + \"\";\\r\\x0avar \\x53a\\x30 =\\x20\"dy\"\\x20+ \"\";\\r\\x0avar Hs\\x32\\x20= \"nseBo\" + \"\";" ascii
    $s13 = "Cg){return BCg;};v\\x61r P\\x4ah = \"ose\" + \"\";\\r\\nvar\\x20N\\x41e\\x30 =\\x20\"cl\" \\x2b \"\";\\x0d\\nfunction \\x52Vy(Mb" ascii
    $s14 = "30643653869\\x363e-10;\\x0d\\n\\x7d \\x65lse\\x20n = 0xefc8249d;\\r\\x0a}\\x3b\\r\\x0areturn mash;\\r\\n}\\r\\n\\r\\n\\x76ar Pe=" ascii
    $s15 = "eturn Math.f\\x6coor(range * (ra\\x77prng() + \\x28rawprng() * 0x200000 | 0)\\x20*\\x201.1102230246\\x3251565e-16)'+''+');\\x0d" ascii
    $s16 = "+Wc+(func\\x74\\x69on Ii(){return\\x20NLs;}()) + RGl2+Hh+UIk+\\x28func\\x74ion VEd()\\x7breturn Uf;}()) + (function Rz(){return " ascii
    $s17 = "t\" + \\x22\";\\r\\nvar FO\\x703 \\x3d\\x20\"l\\x65n\" + \"\";\\r\\n\\x66unction Zb\\x31(CZq\\x29{return CZq;};v\\x61r Pa1 = \"l" ascii
    $s18 = "05;\\r\\nvar UMc=\"437\\x22;\\r\\n\\r\\x0avar E\\x52b=[SUf\\x32+Kx2 + (function Fb('+''+'\\x29{return Ei;}())+Qc4+(function\\x20" ascii
    $s19 = "= \"1\\x3123\" +\\x20\"\";\\r\\nvar \\x4dz\\x39=(BSs\\x34 + If(Kg), Jl9 +\\x20CZy +\\x20IIk2 + (fu\\x6ec\\x74io\\x6e NKy0(){retu" ascii
    $s20 = "\" + \"\";\\r\\nfunction KEx3(TEw){retur\\x6e TEw\\x3b};function OHs\\x30\\x28Lo){r\\x65t\\x75rn Lo\\x3b};var Ly0 = \"p\" + \"\"" ascii

  condition:
    uint16(0) == 0x200a and
    1 of ($x*) and 4 of them
}