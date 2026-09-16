rule sig_20160802_3849c1750de64b54438c1b4745081822 {
  meta:
    description = "datamaliciousorder - file 20160802_3849c1750de64b54438c1b4745081822.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a87e92515fd3cf6162e09167e2acc5c7797a0d3b423e5a21ebd2d7a30f1dc154"

  strings:
    $x1  = "    var aZl8 = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "3tion Ns5(){return LJ\\x61;\\x7d(\\x29)](-1310 + \\x31410);\\r\\n\\t\\t\\t\\x63ontinue;\\r\\n\\t\\t\\x7d\\r\\x0a\\t\\t\\r\\n\\t" ascii
    $s3  = "ction Vg8(\\x45c, DHf1 /\\x2a L  */)\\r\\n{\\r\\n  \\x20 \\x76ar \\x57Hy0=WScript[Bb5 + IJh + \\x28function SWb\\x28){return Fl2" ascii
    $s4  = "57Script[Bb5 + IJh + Fl2 + Fp5](Q\\x67+W\\x74\\x36\\x2bQc(F\\x753)+(functi\\x6fn Tv6(){return \\x52\\x44j;}()) + \\x50Is6\\x20+ " ascii
    $s5  = "\\r\\n\\r\\n\\r\\nfunctio\\x6e VOy7(DH\\x661 \\x2f* L  */\\x29\\r\\x0a{\\r\\n\\x09if (DHf1[0]== 0x4D && DHf1[1]== 0x5a)\\r\\n\\t" ascii
    $s6  = "0;\\r\\nh -= n;\\r\\nn += h * 0x100000000;\\r\\n}\\r\\x0areturn (n >>\\x3e 0) * 2.328\\x3306436\\x35\\x3386963e-10;\\r\\n} else " ascii
    $s7  = "x66unction LBy(){return OXv9;}(\\x29)];\\r\\n\\r\\nvar GRx5=1;\\r\\nv\\x61\\x72\\x20DAe=2;\\r\\nvar Ya=3607 - 3605;\\r\\nvar UMc" ascii
    $s8  = "x48F\\x7a=ne\\x77\\x20\\x41rray();\\r\\n\\tfor (var OP\\x6a=693\\x38 - \\x36938; OPj < Tf0[JQu(QSc\\x29 + (function C\\x6e2(){re" ascii
    $s9  = "\\x2bPo+Cy5\\x20+ Nn5+(f\\x75nction GNn(){retu\\x72n FYs1;}()), Rj3(Sj5)+WSb0+(function Ry0(\\x29{r\\x65turn Q\\x71\\x3b}())+NA" ascii
    $s10 = "\\nma\\x73h = null;\\r\\nvar ra\\x6e\\x64\\x6fm = f\\x75ncti\\x6fn( \\x72ange ) {\\r\\nreturn Math.floor(\\x72ang\\x65 * (rawprn" ascii
    $s11 = "2){return L\\x72;\\x7d;fu\\x6ection \\x58p6\\x28I\\x6b){return Ik;};var Fu3 =\\x20\"O\" + \"\";\\r\\nfunction Vw3\\x28NAa){retur" ascii
    $s12 = "\";\\r\\nfunction ORk1(Ds){return\\x20Ds;};\\x76ar Xz4 = \"se\"\\x20+ \"\";\\r\\nvar Pg3\\x20= \"clo\" + \"\";\\r\\nf\\x75nctio" ascii
    $s13 = "\"eT\" + \"\";\\r\\nvar Fy = \"Sav\" + \"\";\\r\\nfu\\x6ection Nq(O\\x42j){return O\\x42j;\\x7d;functi\\x6fn\\x20ETx9(ZZc8){ret" ascii
    $s14 = "Er8;};functio\\x6e RV\\x79(Mb0){return Mb0;};v\\x61r\\x20Z\\x56t7\\x20= \"le\\x22 + \"\\x22;\\r\\nvar LWr\\x20= \"oFi\" + \"\";" ascii
    $s15 = " Pe0=(Dv3\\x20\\x2b KJd + (function IMn(){return CZi8;\\x7d\\x28))\\x2c Zs5 + Te1 + Su(MSl) + \\x58t6);\\r\\nvar UWy4=Pe0[\\x51S" ascii
    $s16 = "Mz9=\\x28B\\x53s4 + \\x49f(Kg), Jl9 + CZy\\x20+ IIk\\x32 + (functi\\x6fn\\x20NK\\x790(){return EYf;}()));\\r\\nvar Te=\\x4dz9[QS" ascii
    $s17 = "49d;\\r\\x0a}\\x3b\\r\\x0aret\\x75rn mash;\\r\\n}\\r\\n\\r\\nv\\x61r\\x20P\\x65=[NNh + JZe + Sk + \\x57i2 + (func\\x74ion BIy1()" ascii
    $s18 = "5\\x20+ IJh + Fl2 \\x2b Fp5](MVd1(Qg)+Wt6+Fu3+RDj + PIs6 + Wz3);\\r\\n\\t\\tARt[Pc0]()\\x3b\\r\\n\\t\\tARt[(functio\\x6e Cb(){re" ascii
    $s19 = "turn TE\\x64;}()) + Zf+Hh+VUg + RUf\\x2bCp +\\x20IHt+(func\\x74ion Wc6(){return HPu9;}())+NMh(Az1)];\\r\\nvar Ba5=W\\x53crip\\x7" ascii
    $s20 = " \"bj\" + \\x22\"\\x3b\\r\\nvar IJh = \"\\x65ateO\" + \"\";\\x0d\\nvar Bb5 = \"Cr\" + \"\";\\r\\n\\x66unction NMh(Yd6){return Yd" ascii

  condition:
    uint16(0) == 0x200a and
    1 of ($x*) and 4 of them
}