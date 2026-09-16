rule sig_20160802_f13c877e83171181063301340155c414 {
  meta:
    description = "datamaliciousorder - file 20160802_f13c877e83171181063301340155c414.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fcf018058dfbe09346e10fdd7ba720ac98bd6549cd5a821d7c3fe97db2618e03"

  strings:
    $s1  = "    var aJDi = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "ar t = 1768863 * s\\x5bp] \\x2b c * 2.3283064365386963\\x65-1\\x30;\\r\\nreturn s[p] = t - (c =\\x20t\\x20| 0);\\r\\n}ret\\x75rn" ascii
    $s3  = "a\\x37[\\x3254]\\x3d19363 - 9731;\\r\\nPa7[255]=\\x3160;\\r\\n\\t\\r\\n\\tvar\\x20Dq=new Array();\\r\\n\\tvar O\\x67=\"\";\\r\\n" ascii
    $s4  = "9]], false);\\r\\n\\t\\t\\tSy[Ra4 + Bd6]();\\r\\n\\t\\t}\\r\\n\\t\\t\\r\\n\\t\\tif (Sy.rea\\x64ystate < (-1915 \\x2b 1919)) \\r" ascii
    $s5  = "\\x20YFe + JHu8 + Ot8](\\x47J\\x75+OIo+(function Li4(\\x29{retur\\x6e\\x20VT\\x6b0;}())\\x2bIh2 +\\x20GT\\x67 + XHb0);\\x0d\\n" ascii
    $s6  = "\\r\\n\\t\\tAR\\x74[(function NAc\\x33(){ret\\x75\\x72n\\x20G\\x780;}())\\x20+ KGo]=GRx5\\x3b \\r\\n\\t\\tAR\\x74[Ub](Sy[ZWl + (" ascii
    $s7  = "\\x32\\x2bKx2 + (\\x66unction Fb(){return Ei;}\\x28))+Qc4+(function Zq9(){re\\x74urn Nl\\x3b}())+Wn1+\\x52Wi+Po+Cy5 + Nn5+(\\x66" ascii
    $s8  = "){return Tl8;};var Xe1 = \"h\" \\x2b \"\";\\r\\nvar Lm = \"pu\\x73\\x22\\x20+\\x20\"\";\\r\\nvar Rt\\x20= \"At\"\\x20+ \"\";\\x0" ascii
    $s9  = "x65n\" + \"\";\\r\\nfunction DLr5(Bx7){retu\\x72n Bx\\x37;};function Yj\\x28\\x4bf1){r\\x65t\\x75rn Kf\\x31;};var Sh = \"p\" + " ascii
    $s10 = " R\\x56\\x79(Mb0\\x29{return Mb0;\\x7d;var\\x20J\\x47m3\\x20= \"o\\x64y\" + \"\\x22;\\r\\nvar\\x20\\x56Jk5 = \"eB\" + \"\";\\r" ascii
    $s11 = "LT\\x720 = \"\\x6cen\" +\\x20\\x22\";\\r\\nfu\\x6ect\\x69on Ck\\x39(K\\x46j){return KFj;\\x7d;var B\\x72\\x35 = \"TP\" + \"\";" ascii
    $s12 = "+\\x2b)\\r\\n{\\r\\n\\ttry \\r\\n\\t{\\r\\n\\t\\tvar Sy=W\\x53cript[EIk\\x20+ (fu\\x6e\\x63\\x74i\\x6fn SSq(){return YFe;}()) + " ascii
    $s13 = "y[(function YVv()\\x7br\\x65t\\x75rn El;}())]\\x28(function \\x47i2(){return \\x44n\\x3b}()) + VXc, ERb[OEq6+\\x2b % \\x45Rb[QSc" ascii
    $s14 = "{\\x72\\x65turn RMs4;}()\\x29 + V\\x4ak5 + \\x52Vy(JGm3)]);\\x0d\\n\\t\\tARt[NAe0 + PJh + MTj\\x34]=1 * \\x30;\\r\\n\\t\\tARt[(f" ascii
    $s15 = "\"\";\\r\\nfunct\\x69on BZb(YS\\x61)\\x7breturn YSa;};\\x66unction PMq\\x32(Qx){return Qx;};var Ot\\x38 = \"t\" + \"\";\\r\\nvar" ascii
    $s16 = "OPj <\\x20Tf0[J\\x51u(\\x51\\x53c) + (\\x66unction \\x43\\x6e2(){return OXv9;}())]; OPj++)\\r\\n\\t{\\r\\n\\t\\tvar EFq7\\x3dTf0" ascii
    $s17 = "r RGl2 = \"q\" + \"\";\\r\\n\\x76ar Ls = \"ri\" + \"\\x22;\\r\\nfuncti\\x6fn G\\x54n6(Wc){return Wc;};var \\x58\\x735 = \"te\" +" ascii
    $s18 = "1[DHf1\\x5bQSc + OX\\x769]\\x2d1] << 2\\x34;\\x09\\r\\n\\t\\x44Hf1[(function Pq(){return EOp4;}()) + Uj](HFz[QSc + OXv9]-4, 4);" ascii
    $s19 = "GNn(){ret\\x75\\x72n FYs1;}())+Rj\\x33(Sj5), WSb0+Hu + Ry0+VI\\x66 + S\\x635+XCn9+SF\\x68 + To2+Jp1+(function WJf(){return Ja;}(" ascii
    $s20 = "28ENo \\x3c 128\\x29 \\x0d\\x0a\\t\\t\\t{EFq7=\\x45No;}\\r\\n\\t\\telse \\r\\n\\t\\t\\t{EFq7=Pa7[\\x45\\x4eo];}\\r\\x0a\\t\\tDq." ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}