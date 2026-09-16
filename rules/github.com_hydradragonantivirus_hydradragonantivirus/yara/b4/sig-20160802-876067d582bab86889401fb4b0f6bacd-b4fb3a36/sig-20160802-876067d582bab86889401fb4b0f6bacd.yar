rule sig_20160802_876067d582bab86889401fb4b0f6bacd {
  meta:
    description = "datamaliciousorder - file 20160802_876067d582bab86889401fb4b0f6bacd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c91b1d676c747982b151d87811318cf0211ff339dd0a1de7922b0f640c83557"

  strings:
    $s1  = "    var aFFo = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = " >>> 0;\\r\\nh -= n;\\r\\nn += h * 0x100000000;\\x0d\\n}\\r\\nreturn (\\x6e >>> 0) * 2\\x2e32830\\x36\\x34365386963e-10;\\r\\n} " ascii
    $s3  = "nvar WSb0 = \"p:\" + \"\";\\r\\nfunct\\x69on Rj3(TXh){return TXh;};v\\x61r \\x53j5 = \"htt\" + \"\";\\r\\x0avar FYs1\\x20\\x3d " ascii
    $s4  = "\\r\\nvar\\x20Yi \\x3d \"WSc\" + \"\";\\r\\nfunc\\x74ion\\x20\\x4ae4(LFp){return L\\x46p;};function KQd9(\\x5aOc9)\\x7breturn ZO" ascii
    $s5  = "\\r\\n\\x09\\r\\x0a\\x09var Dq=new Array();\\r\\n\\tvar \\x4fg=\"\";\\x0d\\n\\tvar ENo; var EFq7;\\r\\n\\tfo\\x72\\x20(v\\x61r O" ascii
    $s6  = "\\r\\nfunction Va\\x33(On){re\\x74urn On;};function GLo1(Vo2){re\\x74urn Vo2;};var JSw\\x37 = \".\\x35.1\\x22 + \"\\x22;\\r\\nva" ascii
    $s7  = "b\\x39\\x3632]=254;\\r\\nSq[160]=255\\x3b\\r\\n\\t\\r\\x0a\\tva\\x72 HFz=new Array();\\r\\n\\tfo\\x72 (var OPj=6938\\x20- 6938;" ascii
    $s8  = "tion L\\x79(DHf1\\x20/* k \\x20*/\\x29\\x0d\\n{\\r\\n  \\x20 var Pa7\\x3d\\x6eew Array();\\r\\n\\t\\r\\nPa7[128]=199;\\r\\nPa7[1" ascii
    $s9  = "0=WScrip\\x74[KQ\\x649\\x28Ha) + FJq\\x28Ls) + (func\\x74ion \\x4dh(){r\\x65tur\\x6e RGl2;}()) +\\x20WRl3](HVn9+Ff3+(function " ascii
    $s10 = "+MSc5 \\x2b QRy5+RTo2(Lr8)+Un, Cl8\\x2bAe+Y\\x791 + Ri5+(\\x66unction Xl2(){return Dt6;}())+Oj2+On1 + QGq];\\r\\nv\\x61r Ba\\x35" ascii
    $s11 = "nvar Vh \\x3d \"\\x74h\" + \"\";\\r\\nv\\x61r W\\x4b\\x62 = \"leng\" + \"\\x22;\\r\\x0afunction Su(SHv4){return SHv4;};var\\x20X" ascii
    $s12 = "9pt[Ha + Ls + \\x52Gl2 + (funct\\x69on Vq(){return \\x57Rl3;\\x7d()\\x29](Yi + DB\\x73\\x36 + Ph0 + Ni1 + \\x45\\x49k);\\r\\nvar" ascii
    $s13 = "Rt=WSc\\x72ipt[Ha + Ls + RGl2 +\\x20W\\x52l\\x33](HVn9+Ff3+\\x28function C\\x630(){return R\\x75;\\x7d())+Wt6 + Bd6(EDg) + \\x54" ascii
    $s14 = "5ncti\\x6fn STv0\\x28Ra0){return Ra0;};var T\\x56r3\\x20=\\x20\"e\" + \"\";\\r\\nvar \\x54k0 = \"w\\x72it\"\\x20+ \"\";\\x0d\\nf" ascii
    $s15 = "se\\x20\\r\\n\\t\\t\\t{\\x45Fq7\\x3dPa7\\x5bEN\\x6f];}\\r\\n\\t\\tDq.\\x70\\x75sh(String[Kt \\x2b Fd \\x2b XUw + Eo\\x36](EFq7))" ascii
    $s16 = "q(Re1){return Re1;};var WRl3 = \"ct\" + \"\";\\r\\nvar RGl2 = \"eO\\x62je\\x22 + \"\";\\r\\nvar Ls = \"at\\x22\\x20+ \"\"\\x3b" ascii
    $s17 = "r\\n\\t\\tREt2=(REt2\\x20+ DHf1[OP\\x6a]) % 0x100000000\\x3b\\r\\n\\t};\\x0d\\n\\tif (REt2 !=\\x20Cm) {return [];};\\r\\n\\t\\r" ascii
    $s18 = "+ \"\";\\r\\nvar Mz9=(BSs4 \\x2b If(Kg), Jl9 +\\x20CZy\\x20+ IIk2 + (function NKy0(){\\x72etur\\x6e EYf;}(\\x29));\\r\\nvar Te=M" ascii
    $s19 = "){\\x72eturn ITv6\\x3b}\\x3bvar\\x20Is6 = \\x22ty\\x70e\\x22 + \"\";\\r\\nvar JRm3 = \"ope\\x6e\" + \"\";\\r\\nfunction Bd6(S\\x" ascii
    $s20 = "nvar U\\x4dc=\"437\";\\x0d\\n\\r\\nvar ERb=[SUf2+\\x4bx2 + (function Fb(){return Ei;}())+Qc4+(f\\x75nc\\x74ion Zq\\x39\\x28){ret" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}