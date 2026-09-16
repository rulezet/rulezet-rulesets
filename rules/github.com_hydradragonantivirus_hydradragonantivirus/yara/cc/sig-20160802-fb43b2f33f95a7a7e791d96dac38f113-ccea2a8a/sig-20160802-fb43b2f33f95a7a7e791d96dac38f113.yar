rule sig_20160802_fb43b2f33f95a7a7e791d96dac38f113 {
  meta:
    description = "datamaliciousorder - file 20160802_fb43b2f33f95a7a7e791d96dac38f113.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4744b64243f91dc5ed209ad01c15d925d758aeb73e71a3d2d62d16d29711042f"

  strings:
    $x1  = "    var aUo5 = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "f'+''+'unction Tf2(Hg0){return Hg0;}\\x3bvar\\x20FFm = \"GET\\x22 \\x2b \"\\x22;\\r\\nvar\\x20Hp0 = \\x22n\"\\x20+ \"\";\\r\\nva" ascii
    $s3  = "n\\tfor (v\\x61r OPj\\x3d6938 - 6938; \\x4fPj < \\x54f0[\\x4aQu(Q\\x53c)\\x20+ (function Cn2\\x28)\\x7breturn\\x20O\\x58v9;}())]" ascii
    $s4  = "\\r\\n\\t\\x09else\\r\\x0a\\t\\t\\t{v\\x61r \\x45\\x4eo=Sq[E\\x46q7];}\\r\\n\\t\\x09\\x48Fz[(function Gk(){return RUn9;}()) + JV" ascii
    $s5  = "\"\";\\r\\nfunction GTn6(Wc){return Wc;};var Xs5 = \"br\" + \"\";\\r\\nvar Bl = \"://\" + \"\";\\x0d\\nv\\x61r Xi = \"http\" + " ascii
    $s6  = "\\x65\" + \"\";\\r\\nfunction KEx3(TEw){retur\\x6e TEw\\x3b};function OHs\\x30\\x28Lo){r\\x65t\\x75rn Lo\\x3b};var Ly0 = \"p\" +" ascii
    $s7  = "\\r\\x0a\\t{\\r\\n\\t\\tRE\\x742=\\x28REt2 + \\x44H\\x661[O\\x50j]) % 0x100000000;\\r\\n\\t};\\r\\n\\tif (REt2 != Cm) {return []" ascii
    $s8  = "\\x71(){\\x72eturn Ph0;}(\\x29)](Oa4(Ea)+JWz3+Tv6+Ep + Li4 + (function TBc(){return B\\x778;}()));\\r\\n\\t\\tARt[\\x45Sh + Hp0]" ascii
    $s9  = "\\x0av\\x61r Gz = 6721\\x36\\x38;\\r\\nvar Id=NVd[QSc + OXv9];\\r\\nvar Pe0\\x3d\\x28Dv\\x33 + KJd + (function IMn(\\x29{return " ascii
    $s10 = "z4(BCg){return BCg;};v\\x61r P\\x4ah = \"ose\" + \"\";\\r\\nvar\\x20N\\x41e\\x30 =\\x20\"cl\" \\x2b \"\";\\x0d\\nfunction \\x52V" ascii
    $s11 = "\"l\\x6clll\"\\x20+ \"\";\\r\\x0afunct\\x69on Oq(Pf0\\x29{return Pf0\\x3b}\\x3bfunct\\x69on\\x20SGv(KLy5){\\x72et\\x75rn\\x20KLy" ascii
    $s12 = "ction H\\x4aj9(){return Sd0;}()), SU\\x662+GTn6(Bl) + Xs5+(functio\\x6e RGl2(\\x29{return Z\\x66;}())+Ii + QMf2+U\\x67 + RUf+(fu" ascii
    $s13 = "r OOh = \"\\x68\" \\x2b\\x20\"\"\\x3b\\r\\nvar Ud8 \\x3d \"gt\" + \"\"\\x3b\\r\\nva\\x72 FOp3 = \"len\" +\\x20\"\";\\r\\nfunct" ascii
    $s14 = "ar Pe=[JZe + Sk + \\x57i2 + (\\x66u\\x6ec\\x74ion\\x20Ua(){return INw6\\x3b}\\x28)\\x29 + Wk9 + Es1 + VOw,\\x20Ft + DQb +\\x20XE" ascii
    $s15 = "i\\x6fn DYh0(){return Ep;}()) +\\x20(\\x66\\x75\\x6ection YF\\x67\\x28){return Li4;\\x7d()) + \\x42\\x778);\\r\\n  \\x20 WHy0[MP" ascii
    $s16 = "nvar Jn9 \\x3d \"\\x63ript\" + \"\";\\x0d\\nvar Kh = \"WS\"\\x20+ \"\";\\r\\nfunc\\x74ion HS\\x776(XMl6){return XMl6;};var\\x20P" ascii
    $s17 = "n Su(SHv4){return SHv4;};\\x76ar\\x20Xt6 = \"ll\" \\x2b \"\"\\x3b\\x0d\\nvar MSl = \"l\\x6c\" \\x2b \"\";\\r\\nvar Te1 = \"lllll" ascii
    $s18 = "K\\x4bh4){return \\x4bKh4;};var OXv9 = \"\\x67th\"\\x20+\\x20\"\\x22\\x3b\\r\\n\\x76\\x61r Q\\x53c = \"l\\x65n\" + \"\";\\r\\nva" ascii
    $s19 = "x65turn Qa;}()) + Hs2\\x20+\\x20Sa0]);\\r\\n\\t\\tARt[PCl +\\x20Fy]=1 \\x2a\\x200;\\x0d\\n\\t\\tARt\\x5bMs4 +\\x20(f\\x75nction " ascii
    $s20 = "nfor (var OPj=0; OPj \\x3c Pe[QSc + (function FTj(){return OXv9\\x3b}())]\\x3b OPj++)\\x0d\\n{\\r\\n\\x09t\\x72y \\r\\n\\t{\\r" ascii

  condition:
    uint16(0) == 0x200a and
    1 of ($x*) and 4 of them
}