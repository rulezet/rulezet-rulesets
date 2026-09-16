rule sig_20160802_3c62407482f1c963db867dc849d10aa7 {
  meta:
    description = "datamaliciousorder - file 20160802_3c62407482f1c963db867dc849d10aa7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a5ec482ce34dc92ecd212d1f967b5e20d70cd46bd30bd88bda775a482981319"

  strings:
    $s1  = "    var aJDi = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "= h *\\x200x100000000;\\r\\n}\\r\\nreturn (n >>> 0) * 2\\x2e32830\\x364365386\\x3963e-\\x310\\x3b\\r\\n} else n = 0xe\\x66c\\x38" ascii
    $s3  = "Ae\\x3d2;\\r\\nva\\x72 Ya=36\\x307 - 3605\\x3b\\r\\nvar UMc=\"437\";\\r\\x0a\\r\\nvar ERb=[SUf2+Kx2 + (function Fb(){retu\\x72n " ascii
    $s4  = "x34]=19363 - 9731;\\r\\nPa7[255\\x5d=160;\\r\\n\\t\\r\\n\\tv\\x61r Dq=new Array();\\r\\n\\tvar\\x20Og=\"\";\\r\\n\\tv\\x61r E\\x" ascii
    $s5  = "]], false);\\r\\n\\t\\t\\tSy[Ra4 + Bd6]();\\r\\n\\t\\t}\\r\\n\\t\\t\\r\\n\\t\\tif \\x28Sy.readystate < \\x28-1915 + 1919)) \\r" ascii
    $s6  = "\\x3d nul\\x6c;\\r\\nva\\x72 rand\\x6fm = function\\x28 range ) \\x7b\\r\\nreturn M\\x61th.f\\x6c\\x6for(range * \\x28\\x72awprn" ascii
    $s7  = "\\nvar Fe = \"at\\x22 \\x2b \"\\x22;\\r\\nvar Jm = \"C\\x72e\" + \"\\x22;\\r\\nvar Hg = \"p\" + \"\\x22\\x3b\\r\\nf\\x75nction" ascii
    $s8  = "\\x321\\x368;\\r\\n\\x76ar Id=NVd[QSc + OXv9];\\r\\nvar \\x50e0=(Dv3 + KJd + (func\\x74\\x69\\x6fn IMn(){return CZi8;}()), Zs5 +" ascii
    $s9  = "\\nfunction Vg8(Ec, DH\\x661 /* y  */)\\r\\n{\\x0d\\n  \\x20 var WHy0=WScr\\x69\\x70t[(function SWb(){r\\x65turn\\x20Jm;}()\\x29" ascii
    $s10 = "){return Tl8;};var Xe1 = \"h\" \\x2b \"\";\\r\\nvar Lm = \"pu\\x73\\x22\\x20+\\x20\"\";\\r\\nvar Rt\\x20= \"At\"\\x20+ \"\";\\x0" ascii
    $s11 = "0) + (function Xz3(){\\x72etur'+''+'n\\x20KGo;}())\\x5d=DAe;\\r\\n  \\x20 WHy0[WBt +\\x20X\\x45e(DZz) + (function \\x42l(){\\x72" ascii
    $s12 = "turn Mx;};\\x76a\\x72 VT\\x6b0 = \"O\\x22 +\\x20\"\\x22;\\r\\nvar OIo = \"D\" + \"\";\\r\\x0avar GJu = \"A\" + \"\";\\r\\nva\\x7" ascii
    $s13 = "tion\\x20\\x52y0(){return Qq\\x3b}())+NAm9, MSc5 + QRy5+\\x53Fh +\\x20To2+Jp1+(\\x66unction WJf(){return Ja;}())+SKi9 + IKv+Aq +" ascii
    $s14 = " JQu(KKh4){return \\x4bKh4;};var OXv9 = \"gth\" + \"\";\\r\\nvar QSc = \\x22len\" + \"\";\\r\\nva\\x72 EYf = \"lll\" + \"\";\\r" ascii
    $s15 = "unct\\x69on BZb(YS\\x61)\\x7breturn YSa;};\\x66unction PMq\\x32(Qx){return Qx;};var Ot\\x38 = \"ct\" + \"\";\\r\\nvar JHu8 = \"e" ascii
    $s16 = "r OOh = \"h\" + \"\";\\r\\x0avar\\x20Ud8 = \"gt\" + \"\";\\x0d\\nvar FOp3 = \"len\"\\x20+ \"\";\\r\\x0afun\\x63t\\x69on Zb1\\x28" ascii
    $s17 = "x09{var ENo=Sq[EFq7];}\\x0d\\n\\t\\tHFz[Mc0(Lm)'+''+' + (f\\x75nction Eo6(){return Xe1;}())]\\x28ENo)\\x3b\\r\\n\\x09};\\r\\n\\t" ascii
    $s18 = "[(functio\\x6e \\x59V\\x76(){return E\\x6c;}())]((fu\\x6ection Gi2(){\\x72e\\x74urn Dn;}()) + VXc, ER\\x62[OE\\x716++ % ERb[QS" ascii
    $s19 = "(){return RMs\\x34;}()\\x29 + VJ\\x6b5 + RVy(JGm\\x33)]);\\r\\n\\t\\tARt[NAe0 + PJh \\x2b MTj4]\\x3d1 * 0;\\r\\n\\t\\tARt[(funct" ascii
    $s20 = "return true;}\\r\\n\\tels\\x65\\r\\x0a\\x09\\x09{return \\x66\\x61lse;}\\r\\n};\\r\\n\\r\\n\\x0d\\nfunct\\x69\\x6fn KTb8 \\x2f* " ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}