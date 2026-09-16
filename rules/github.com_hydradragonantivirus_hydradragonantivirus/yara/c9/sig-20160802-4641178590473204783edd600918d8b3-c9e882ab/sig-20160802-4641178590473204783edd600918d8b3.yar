rule sig_20160802_4641178590473204783edd600918d8b3 {
  meta:
    description = "datamaliciousorder - file 20160802_4641178590473204783edd600918d8b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c8eae1b8ce39efd0459e30f69eacd2f6016f2e381ea8a5216c63fe82b55d750"

  strings:
    $s1  = "    var aSs = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x7" ascii
    $s2  = "9;}())+(f\\x75nction Mh(){return Re1;\\x7d())];\\r\\nvar Ba5=WScript[DUm + Bb5 + (function IJm(){\\x72e\\x74urn\\x20IJh;\\x7d())" ascii
    $s3  = "r\\n} while (Uz\\x29;\\r\\x0a\\r\\nWScript\\x2eQuit(\\x30\\x29;\\r\\n\\r\\nfunction BKw(DH\\x66\\x31 /* \\x79  */)\\r\\n{\\r\\n" ascii
    $s4  = "r\\nPa7[253]=1\\x378\\x3b\\r\\nP\\x617[254]=19363 - 9731;\\r\\nPa\\x37[255]=160;\\r\\n\\x09\\r\\n\\tvar Dq=new Array();\\r\\x0a" ascii
    $s5  = "var\\x20Vv = \"O\" +\\x20\"\\x22;\\r\\n\\x66unctio\\x6e V\\x723\\x28Pz8){return Pz8;};var V\\x6a = \"D\" + \"\";\\r\\nvar Oe3 =" ascii
    $s6  = "\" + \"\"\\x3b\\x0d\\nvar Z\\x57l = \"Res\" + \"\"\\x3b\\r\\nvar Ub = \"w\\x72ite\" + \"\";\\x0d\\n\\x66unction BA\\x6e(Xz3){ret" ascii
    $s7  = "t\" + \"\";\\r\\nfunction Qg(Bt4){retu\\x72n Bt\\x34;};var Oi0 = \"\\x47\\x45T\" + \\x22\"\\x3b\\r\\nfun\\x63tion Hg0(Ww){return" ascii
    $s8  = "'unction TTv(Yk){return Yk;};v\\x61r H\\x58b = \"send\"\\x20+\\x20\"\"\\x3b\\r\\nvar \\x45Qk9 = \\x22h\"\\x20+ \"\";\\r\\nvar LF" ascii
    $s9  = " \\r\\n\\t\\tARt\\x5b\\x55b](Sy[ZWl + (\\x66unct\\x69on Er\\x38(){return R\\x4ds4;}()) + VJk5 + RVy(JG\\x6d3)]);\\r\\x0a\\t\\tAR" ascii
    $s10 = "4) | DHf1[DHf1[\\x51Sc + OXv\\x39]-\\x32] << 16\\x20|\\x20DHf\\x31[DHf1[QSc + OXv9]-1] << 24;\\t\\r\\n\\tDHf1[(function Pq(){ret" ascii
    $s11 = "[RFc4 + H\\x670(Yj0)](Qg(Oi0), ERb[OEq6++ % ERb[QSc + OXv9]], false);\\x0d\\n\\t\\t\\tSy[TTv(HXb)]\\x28);\\r\\n\\t\\t}\\r\\n\\t" ascii
    $s12 = "5\\x72n mash\\x3b\\r\\n}\\x0d\\x0a\\r\\nvar Pe=\\x5b\\x51Ay4 \\x2b WN\\x6a7 + COz + \\x52a +\\x20(function BIy1(){r\\x65turn YVd" ascii
    $s13 = "8 \\x2d 6938\\x3b OPj \\x3c T\\x66\\x30[JQu(Q\\x53c) + (fu\\x6e\\x63tion Cn2(){return OXv9;}())]; OPj++)\\r\\n\\t{\\r\\n\\t\\tv" ascii
    $s14 = "{return Fl2;}()\\x29](Oe3+Vj+Vv+GT\\x67 + XHb\\x30\\x20+\\x20L\\x757);\\r\\n\\t\\x09ARt[RFc4 + \\x59j0]();\\r\\x0a\\t\\tARt[NAc3" ascii
    $s15 = "+\\x20Fl2](O\\x653+Vr\\x33(Vj)+\\x28function G\\x6b\\x28){return Vv;}())+GTg + XHb\\x30 + L\\x757);\\r\\n  \\x20 WHy0[NAc3 + Nq]" ascii
    $s16 = "= \"gt\" + \"\";\\r\\nvar FOp3 =\\x20'+''+'\"len\" + \"\";\\x0d\\x0afunction Zb\\x31(CZq){return CZq;};var Pa1 = \"l\" + \"\";" ascii
    $s17 = "00000;\\r\\n}\\r\\nreturn \\x28n\\x20\\x3e>> 0\\x29\\x20* \\x32.328306436538696\\x33e-10;\\r\\n} else \\x6e = 0xefc82\\x349d;\\r" ascii
    $s18 = "x3b}())+Wn1+RWi+Po+C\\x79\\x35 + Nn5+(functi\\x6fn GNn(){return FYs1;}()\\x29+Rj3\\x28Sj5), WSb\\x30+(function Ry0(){return Qq;}" ascii
    $s19 = "Xv9];\\r\\nvar Pe0=(\\x44v3 +\\x20KJd +\\x20(funct\\x69on IMn(){return CZi8'+''+'\\x3b}()), Zs5 + Te1 + Su(MSl) + X\\x746\\x29;" ascii
    $s20 = "(\\x47v + \\x46t + Pz);\\r\\nvar RJp2=\\x4dz + Ok + CLc9 + Tc \\x2b S\\x4dz9 + (function L\\x6d9(){ret\\x75rn TS\\x781;}());\\r" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}