rule _20160802_77a6f6cf3e0f78cae757f2bd4a154af7_20160802_e0400fedc828_243 {
  meta:
    description = "datamaliciousorder - from files 20160802_77a6f6cf3e0f78cae757f2bd4a154af7.js, 20160802_e0400fedc8281a195e4a7afae5a83a43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3accddde82b59692503050c64db82f4e99ae1f1a8e4edb34ff38569639ed6cdf"
    hash2       = "72a1a47fb17ef653d3f0a953854ee9896da0e694484e722a9437b053f4028a66"

  strings:
    $s1  = "[p] = t - (c = t | 0);\\x0d\\n}r\\x65turn random\\x3b}())\\x3b};\\r\\n\\r\\nfunction Mash() \\x7b\\r\\nvar n = 0xefc8249d;\\r\\x" ascii
    $s2  = "j=693\\x38 - 69\\x338; OPj < Tf0[\\x4aQu(QS\\x63) +\\x20(fun\\x63ti\\x6fn Cn2(){return \\x4fX\\x769;}())\\x5d;\\x20OPj++)\\r\\n" ascii
    $s3  = "n G\\x692(){return Mf;}()) + MV\\x641]\\x28\\x29;\\r\\n\\t\\t}\\x0d\\n\\t\\x09\\r\\n\\t\\x09if (Sy.readystate < (-1915 + 1\\x391" ascii
    $s4  = "n\\t\\t\\t\\x7bvar E\\x4eo=Sq[\\x45Fq\\x37\\x5d;}\\r\\n\\t\\t\\x48Fz[(func\\x74\\x69on Gk(){return RUn9;}()) + JVi](ENo);\\r\\n" ascii
    $s5  = "\\x20< 128) \\r\\n\\t\\t\\t{E\\x46q\\x37=EN\\x6f;}\\r\\n\\t\\telse \\r\\n\\t\\t\\t{EFq7=Pa\\x37[ENo];}\\r\\n\\t\\tD\\x71.push(St" ascii
    $s6  = "\\nvar Fe = \"\\x61t\" + \"\";\\r\\x0av\\x61r Jm = \"Cre\" \\x2b \"\";\\r\\nvar H\\x67 = \"qbf9\" + \"\";\\r\\nfuncti\\x6fn Bb5(" ascii
    $s7  = "x63\\x74ion Su(SHv4){return SHv4;};var\\x20Xt\\x36 = \"ll\" + \"\\x22;\\r\\n\\x76\\x61r MSl = \"ll\" \\x2b \"\\x22;\\r\\nvar Te1" ascii
    $s8  = "n\\t{\\r\\x0a\\t\\tREt2=(\\x52Et\\x32 + DHf1\\x5bO\\x50j])\\x20% 0x100000000;\\r\\n\\t};\\r\\n\\tif (REt2 != Cm) {return [];};" ascii
    $s9  = "i8;}()), Zs5\\x20+\\x20Te1 \\x2b Su(MSl) + Xt6);\\r\\nvar UWy4=P\\x650[QSc + (function LBy\\x28\\x29\\x7breturn OXv9;}())];\\r" ascii
    $s10 = "unction JQu(KKh4\\x29{return KKh\\x34;};var OXv9 = \"gth\\x22 + \\x22\"\\x3b\\r\\x0a\\x76ar\\x20\\x51Sc \\x3d \"len\"\\x20+ \"\"" ascii
    $s11 = "k4(TXy)+(fun\\x63\\x74ion RGl2(){ret\\x75rn Gr4;}()) + (function\\x20Ii()\\x7breturn TE\\x64;}()) + Zf+Hh+VUg + RUf+Cp + IHt+(fu" ascii
    $s12 = "x20\"ll\\x6c\" + \"\";\\r\\nvar IIk2 = \"l\\x6c\" + \"\";\\r\\nvar CZy = \"ll\" + \"\";\\r\\nvar Jl9 =\\x20\"lllll\" + \"\";\\r" ascii
    $s13 = "m + \\x46e +\\x20JHu8 + Ot8](\\x4fa4(Ea)+JWz3+Tv6+Ep + Li4 + (function TBc(){return Bw8;}\\x28)));\\r\\n\\t\\tARt[ESh \\x2b Hp0]" ascii
    $s14 = "n INw6;}()) + Wk9 + Es1 + VOw\\x2c Ft + DQb + XEh];\\r\\n\\r\\nfor (var OPj=0; \\x4fPj < \\x50e[QSc +\\x20(fun\\x63t\\x69on FTj(" ascii
    $s15 = "20= mash(Gz);\\r\\nma\\x73h = nul\\x6c;\\r\\nvar random = f\\x75\\x6e\\x63tion(\\x20rang\\x65 ) \\x7b\\r\\nreturn Math.floor(ran" ascii
    $s16 = " \"\\x22;\\r\\nvar\\x20\\x44\\x46m0 =\\x20\\x22:/\\x2fr\" + \"\";\\r\\nfunc\\x74io\\x6e Kx\\x32(Ei){return \\x45i;};var SUf2 = " ascii
    $s17 = " + (fun\\x63tion NKy0()\\x7breturn EYf;}()));\\r\\nvar Te=M\\x7a9[QSc + OXv9];\\x0d\\nva\\x72 NVd=(Mj + (function Oi5()\\x7bretu" ascii
    $s18 = "o\" + \"\";\\r\\nvar Zf = \"t\" + \"\";\\r\\nvar TEd = \"ea\" + \"\";\\r\\nvar Gr4 = \"/b\" + \"\";\\r\\nfunct\\x69on\\x20TNk4(X" ascii
    $s19 = "4 + Pa1);\\r\\nva\\x72 \\x47z = 672168;\\x0d\\x0avar Id=NVd[QSc + OXv9];\\r\\nvar Pe0=(D\\x76\\x33 +\\x20KJd + (function IMn(){r" ascii
    $s20 = "QRSTU\\x56WXYZ\\x61bcdefghijklmnopqrst\\x75vwxyz0123456789+/\";\\x0d\\nv\\x61r mash = Mash();\\x0d\\nfor (i\\x20= 0; \\x69 < o; " ascii

  condition:
    (uint16(0) == 0x200a and (8 of them)
    ) or (all of them)
}