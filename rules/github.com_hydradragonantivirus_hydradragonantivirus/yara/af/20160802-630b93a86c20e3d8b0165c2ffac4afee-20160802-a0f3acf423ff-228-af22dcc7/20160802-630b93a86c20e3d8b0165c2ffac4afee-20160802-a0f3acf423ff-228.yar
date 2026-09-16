rule _20160802_630b93a86c20e3d8b0165c2ffac4afee_20160802_a0f3acf423ff_228 {
  meta:
    description = "datamaliciousorder - from files 20160802_630b93a86c20e3d8b0165c2ffac4afee.js, 20160802_a0f3acf423ff3bbbf01be38c2a7d9bf0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "35e629db4eca7ae2e6b38a341b903e124f0100116de03facbacf6000f711dae7"
    hash2       = "134cbffec974fd70b8a0680bedf7e846cfda8638cb1d70240978532e65c63a0c"

  strings:
    $s1  = ";\\r\\n\\t\\t}\\r\\n\\t\\t\\r\\n\\t\\x09v\\x61r\\x20ARt=WScript\\x5b(function \\x50Xo9(){return\\x20C\\x59i;}()) + DBs6 + (func" ascii
    $s2  = "0=WScript[CYi + DBs6 + P\\x680 \\x2b\\x20\\x4ei1](\\x51g+Wt6+Qc(F\\x753)+(function Tv\\x36\\x28){return \\x52Dj;\\x7d()) \\x2b P" ascii
    $s3  = "\\t\\r\\n\\x09\\x76\\x61r HFz=new Array();\\r\\n\\t\\x66or (\\x76ar \\x4fPj=6938 - 6938; OPj < \\x54f0[JQu(QSc) + \\x28functio" ascii
    $s4  = "};\\r\\n\\r\\x0a\\r\\nfuncti\\x6fn \\x56Oy7(DHf\\x31 \\x2f* L\\x20 */)\\r\\n{\\r\\n\\tif (DHf1[0]== 0x4D && DHf1[1]== 0x5a)\\r" ascii
    $s5  = "t\\r\\n\\t\\tB\\x615[VTd](RC\\x6e + HIy6)\\x3b\\r\\n\\t\\tbreak;\\r\\n\\t}\\r\\n\\tcatch (\\x65) {WScript[LJa](1000); continue;}" ascii
    $s6  = "\\x72n EGw;}\\x28)\\x29 + Dh5 + \\x43a8 + (function \\x45Po(){re\\x74urn Wp;}())\\x20+ Xc6\\x20\\x2b Zb1(YUc) + ZDo7 + Ol + \\x4" ascii
    $s7  = "\\x2b\\x20\"\";\\r\\nva\\x72 Ft = \"EM\" + \"\"\\x3b\\r\\nvar Gv \\x3d \"%T\"\\x20+ \"\";\\r\\x0afu\\x6ection PI\\x7a0(Qz\\x29{r" ascii
    $s8  = "\\r\\nn += h * 0x100000000;\\r\\n}\\r\\nreturn (n >>\\x3e 0) * 2.3283\\x3064365386963\\x65-10;\\r\\x0a\\x7d else n = 0xefc8249d;" ascii
    $s9  = "\\r\\nva\\x72\\x20Vm\\x20= \"ub\" + \"\";\\r\\n\\x76ar\\x20DFm\\x30 = \"://s\" + \\x22\";\\r\\nfunction Kx2\\x28E\\x69){return E" ascii
    $s10 = "\\x20\"\";\\r\\nvar Sy8 = \"ML\" + \"\";\\r\\nvar IFc4 = \"M\\x53\\x58\" \\x2b \"\";\\r\\n\\x66unction QKv(Dq8){return Dq8;};fun" ascii
    $s11 = "x65turn m\\x61s\\x68;\\x0d\\n}\\r\\x0a\\r\\nvar Pe=[Lf7 + \\x28f\\x75n\\x63tion Ra(){return Bq\\x31;}()) + GW\\x79 + Xx4 + NId1 " ascii
    $s12 = "= \"o\" + \"\";\\r\\nvar TEd = \"ot\" + \"\";\\r\\nvar Gr4 = \"/f\" + \"\";\\r\\nfun\\x63ti\\x6fn TNk4(Xs5){return X\\x73\\x35;}" ascii
    $s13 = ")\\x7breturn CZi8;}()), Zs5 + Te1 \\x2b Su(MSl) + Xt6);\\r\\nvar\\x20\\x55\\x57y4=Pe0[QSc + (function LBy(){return OXv9;}())\\x5" ascii
    $s14 = "Wl\\x37) + Zk(Nt0), IFc4 + Sy8 + IZl7 + Yv3(\\x44Qb)];\\x0d\\n\\r\\nfor \\x28var \\x4fP\\x6a=0; OPj < Pe[QSc\\x20+\\x20(function" ascii
    $s15 = "0\\x5bJFi2 +\\x20KVy](Ly(DHf\\x31 /*\\x20L  */)\\x29;\\r\\n  \\x20 WHy\\x30[Fy + (function NA\\x650(){'+''+'\\x72etur\\x6e UWx3;" ascii
    $s16 = "turn OXv9;}())]; OPj++)\\r\\n\\t{\\r\\n\\t\\tva\\x72 EFq7=T\\x66\\x30[SMe3 + Ec9 + Ka](OP\\x6a)\\x3b\\x0d\\n\\t\\tif (EFq7 \\x3c" ascii
    $s17 = "Zy + IIk2 + (function NKy0(\\x29{return EYf;}(\\x29));\\x0d\\nvar Te=Mz9[QSc + OXv9];\\r\\n\\x76ar N\\x56d=(Mj +\\x20(function O" ascii
    $s18 = "(f\\x75nction\\x20Zq9(){re\\x74urn Nl;}())+Wn1+R\\x57i+Po+Cy5 + Nn5+(function GNn(){return FYs\\x31;}\\x28))+Rj3\\x28\\x53j5)+WS" ascii
    $s19 = "turn\\x20Ph0;}()) + Ni1](MVd1(Qg)+Wt6+Fu3+RDj + PIs6 + Wz3);\\r\\n\\t\\t\\x41Rt[Pc0]();\\r\\n\\t\\tAR\\x74[(function Cb(){r\\x65" ascii
    $s20 = "(function\\x20Ii(){return TEd;}()) + \\x5af+Hh\\x2bVUg + RUf\\x2bCp + IHt+(function Wc6(){return HPu9;}())+YJa + \\x4eMh];\\x0d" ascii

  condition:
    (uint16(0) == 0x200a and (8 of them)
    ) or (all of them)
}