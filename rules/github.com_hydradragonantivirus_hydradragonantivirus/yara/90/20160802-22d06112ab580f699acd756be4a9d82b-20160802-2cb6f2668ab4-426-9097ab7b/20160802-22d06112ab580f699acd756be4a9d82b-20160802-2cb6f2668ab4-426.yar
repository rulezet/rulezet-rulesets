rule _20160802_22d06112ab580f699acd756be4a9d82b_20160802_2cb6f2668ab4_426 {
  meta:
    description = "datamaliciousorder - from files 20160802_22d06112ab580f699acd756be4a9d82b.js, 20160802_2cb6f2668ab42e30696488ade460fcca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ec64b5ec9887262cef23b36b49b2ab14d01445b2acddf34537b2b6041ca4399"
    hash2       = "852d0796e12d341203494e4464d4564bf7926eb4028fcaaa0c4259fbe8a11e22"

  strings:
    $s1  = "FJq+H\\x78 + (function \\x49Jh(){return \\x43a;}())+Hg+FEe];\\x0d\\nvar\\x20Ba\\x35=WScript[\\x45\\x718 + KEy7 + Jy7 \\x2b\\x20L" ascii
    $s2  = "\\nret\\x75rn \\x73[p] = t - (\\x63 = t\\x20| 0);\\r\\n}return random;\\x7d());};\\r\\n\\r\\nfunction Mas\\x68() {\\r\\nvar n = " ascii
    $s3  = "\\x20+ (f\\x75nction LBy(){return OXv9;}()\\x29];\\r\\n\\r\\nvar GRx5=1;\\r\\nva\\x72\\x20\\x44Ae=2;\\r\\nvar Ya=3607 - 3605;\\r" ascii
    $s4  = "turn Mf;}()) + M\\x56d1\\x5d\\x28);\\r\\n\\t\\t\\x7d\\r\\n\\x09\\t\\r\\n\\x09\\tif (Sy.readystate < (-1915 + \\x31919)) \\r\\n" ascii
    $s5  = "\\r\\x0avar Mz9=(\\x42S\\x734 + I\\x66(Kg), Jl9 + CZy \\x2b IIk2\\x20+ (functio\\x6e \\x4eKy\\x30(){return EYf;}()));\\r\\nvar T" ascii
    $s6  = "\\x39+MSc5 + QRy5+RTo2(Lr8)+U\\x6e+Cl8+Ae+Yy1 + Ri5+(functi\\x6fn Xl2(\\x29{return D\\x746;}())+Og0, Xs5 +\\x20Lq3+Wc+(function " ascii
    $s7  = "0av\\x61r Pe0=(Dv3 \\x2b\\x20KJd + (function IMn(){return CZi8;}\\x28\\x29),\\x20Zs5 + Te1 + Su(MSl) + X\\x746);\\r\\nvar UWy4=P" ascii
    $s8  = "r V\\x68 = \"th\" +\\x20\"\";\\r\\nvar WKb\\x20=\\x20\"leng\" + \"\";\\r\\nfuncti\\x6fn S\\x75(SHv4){return SHv4;\\x7d;var Xt6 =" ascii
    $s9  = "x797 + Jy7 + LX\\x77](Oa4(Ea)+JWz3+Tv6+Ep + Li4 + (function TBc(){return Bw\\x38;}()));\\r\\n\\t\\tARt[E\\x53h + Hp0]();\\r\\n" ascii
    $s10 = "l\" + \"\";\\r\\nvar Jl9 \\x3d \"lllll\" + \"\";\\r\\nfunction If(YBe){return \\x59Be;};var Kg = \\x22132\" + \"\";\\r\\nvar BSs" ascii
    $s11 = "20Un = \"edam\" + \"\";\\r\\nfun'+''+'cti\\x6fn\\x20RTo2(Xh1\\x29{return Xh1;};var L\\x728 = \"noa\\x72r\" + \"\"\\x3b\\r\\nvar " ascii
    $s12 = ";\\r\\n\\r\\x0avar \\x45Rb=[S\\x55f2+Kx2\\x20+ (function Fb(){ret'+''+'\\x75rn Ei;}())+Qc4+(function Zq9(\\x29{\\x72eturn \\x4el" ascii
    $s13 = "x0avar Me =\\x20\"WScr\\x22\\x20+ \"\";\\r\\n\\x66unction BZb(YSa\\x29{return Y\\x53a;};f\\x75nction\\x20PM\\x712(Qx){re\\x74urn" ascii
    $s14 = "Ua(){return \\x49Nw6;}()) + Wk9 + Es1 + VOw, Ft + DQb \\x2b XEh]\\x3b\\r\\n\\r\\nfor\\x20(var\\x20O\\x50j=0; OPj < Pe[QS\\x63 " ascii
    $s15 = "0\\x3b\\r\\n} el\\x73e\\x20n\\x20= 0\\x78efc8249d;\\r\\n};\\r\\nr\\x65t\\x75r\\x6e mash;\\r\\n}\\r\\n\\r\\nvar Pe\\x3d[JZe + Sk " ascii
    $s16 = "69(){return NLs;\\x7d()) + RGl2+Hh+UIk+(func\\x74ion \\x56Ed(){retu\\x72n Uf;}()) + (function Rz(){return Je4;}())+JFw(E\\x56b) " ascii
    $s17 = "(function Hd(){\\x72eturn RFa9;}()) + Lm9 + RAx6;\\r\\nvar RCn=RJp2 + Mx + \\x4ds\\x3b\\r\\n\\r\\x0afunc\\x74ion uheprng() {\\x7" ascii
    $s18 = "9{\\r\\n\\t\\tREt\\x32=(\\x52Et2 + D\\x48f\\x31[OP\\x6a]) % 0x100000000;\\r\\n\\t};\\r\\n\\tif (REt2 != Cm) {return [];};\\r\\n" ascii
    $s19 = "a;}()) + Hs2 \\x2b \\x53a0]);\\r\\n\\t\\tARt[PCl + \\x46y]=1 *\\x20\\x30;\\r\\x0a\\t\\tARt[\\x4ds4 + \\x28fu\\x6ection Er8\\x28)" ascii
    $s20 = "dq2(LXw)](Dy6(Ea)+JWz3+Tv6\\x2b(\\x66\\x75\\x6ection DY\\x68\\x30(){return Ep;\\x7d()) + \\x28\\x66unction\\x20YFg(){re\\x74ur" ascii

  condition:
    (uint16(0) == 0x200a and (8 of them)
    ) or (all of them)
}