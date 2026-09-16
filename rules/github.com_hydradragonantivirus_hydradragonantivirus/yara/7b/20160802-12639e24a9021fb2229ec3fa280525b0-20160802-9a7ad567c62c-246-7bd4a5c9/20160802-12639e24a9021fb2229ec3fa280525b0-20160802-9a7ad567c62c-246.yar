rule _20160802_12639e24a9021fb2229ec3fa280525b0_20160802_9a7ad567c62c_246 {
  meta:
    description = "datamaliciousorder - from files 20160802_12639e24a9021fb2229ec3fa280525b0.js, 20160802_9a7ad567c62cfaab314f58f47c245677.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7bb39f9014d2e60c94e825f147b955e29f9e186932dc6d4742ac340451f98382"
    hash2       = "a52d52ac269c791cb972b0f3596c667526105de45a2b67b875710fc5dd43b4a0"

  strings:
    $s1  = "\\x28\\x29{return Dt6;}(\\x29)+Oj2+Xs5 + Lq3+Wc+(fun\\x63tion\\x20Ii(){retu\\x72n NLs;}()) + RGl2+Hh+IVm];\\r\\nvar Ba5=WScript[" ascii
    $s2  = "\\t{return false;}\\r\\n\\x7d;\\r\\n\\r\\x0a\\r\\nfunctio\\x6e KTb8 /* \\x6b\\x20 *\\x2f(Ec)\\r\\n{\\r\\n \\x20  var W\\x48y0=WS" ascii
    $s3  = "x69nue;\\r\\n\\t\\t}\\r\\n\\t\\x09\\r\\n\\t\\tvar ARt=WScript[RJe4 + LFp + (function CYi(){return\\x20As3;}()) + (func\\x74ion E" ascii
    $s4  = "0x\\x3100000000;\\r\\n}\\r\\nreturn (n >>> 0) * 2.32830643653869\\x363e-10;\\r\\n} el\\x73e n = 0xefc\\x38249d;\\x0d\\x0a};\\r" ascii
    $s5  = "/* k  */)\\r\\n{\\r\\n\\tif\\x20(D\\x48\\x66\\x31[0]=\\x3d 0x4D && D\\x48f1[1]== 0x5a)\\r\\n\\x09\\x09{return t\\x72ue;\\x7d\\r" ascii
    $s6  = "turn Og;\\r\\n\\x7d;\\r\\n\\r\\n\\r\\nfu\\x6ectio\\x6e Vg8\\x28Ec, \\x44H\\x66\\x31 /* k  */\\x29\\r\\n{\\r\\n    var WHy0=WScri" ascii
    $s7  = "29;\\x0d\\nvar Gz = 6\\x37\\x32168;\\r\\nvar Id=NVd[QSc + OXv9];\\r\\nvar \\x50\\x650=\\x28Dv3 + KJd + (function I\\x4dn(){retur" ascii
    $s8  = "\" + \"\";\\r\\nfunct\\x69o\\x6e U\\x70(Wr6){return W\\x726;};va\\x72 Zu = \"t\" + \"\";\\r\\nva\\x72\\x20As3\\x20= \"jec\\x22" ascii
    $s9  = "x20\"lll\\x6cl\" + \"\\x22;\\r\\nfu\\x6ection Oq(\\x50f0){return \\x50f\\x30;};fu\\x6ect\\x69on SGv(KLy\\x35){\\x72et\\x75rn KLy" ascii
    $s10 = "on Su(SHv4){return SHv4\\x3b};\\x76ar Xt6 = \"l\\x6c\" +\\x20\\x22\";\\r\\nvar MSl =\\x20\"l\\x6c\" + \"\";\\r\\nvar Te1 = \"lll" ascii
    $s11 = "29,\\x20Zs5 \\x2b Te1 + Su(MSl) + Xt6);\\r\\nvar \\x55Wy4=Pe0[QSc + (functi\\x6f\\x6e\\x20LBy(){return OXv9;}())];\\r\\n\\r\\nva" ascii
    $s12 = "2etur\\x6e Ei;}(\\x29)+Qc4+\\x28function\\x20Zq9(){return Nl;}\\x28))+Wn1+RWi+Po+Cy5 + Nn5+(function GNn(){r\\x65tu\\x72n FYs1" ascii
    $s13 = "))+Rj3\\x28Sj5), WSb0+(function Ry0\\x28){return Qq;}())+NAm9+MSc\\x35 + QRy\\x35+RTo2(Lr8\\x29+Un+Cl8+Ae, Yy1 +\\x20Ri5+(functi" ascii
    $s14 = "+ LF\\x70 + As\\x33 + (function \\x57c6(){return \\x5au;}())](Ot8 + D\\x57b8 +\\x20SS\\x71);\\r\\nvar M\\x7a\\x3dBa5.ExpandEnvir" ascii
    $s15 = "ction \\x4eKy0(){return EYf;}()));\\r\\nva\\x72 Te=Mz9[QSc + \\x4fXv9\\x5d;\\r\\nvar NVd=(Mj + (function\\x20Oi5(\\x29{return\\x" ascii
    $s16 = "+ \\x41s3 + (function Wc0(){retu\\x72n\\x20\\x5a\\x75;}())](T\\x59\\x6a+(function Gi\\x32(){ret\\x75\\x72n Cc0;}\\x28))+Wt6+X\\x" ascii
    $s17 = " + \"\";\\r\\nvar IIk\\x32 = \"ll\" + \"\";\\r\\nvar CZy = \"ll\" + \"\";\\r\\nvar\\x20Jl9 = \"lllll\" \\x2b \"\";\\r\\nfunction" ascii
    $s18 = "1r RCn=RJp2 + FGa + LIz;\\x0d\\n\\r\\nfunction uheprng() {return (function() {\\r\\nvar o \\x3d \\x348, \\x63 = 1\\x2c p = o, s " ascii
    $s19 = "+ % ERb[QSc + OXv9]], \\x66al\\x73\\x65);\\r\\n\\t\\t\\x09Sy\\x5bLEs\\x37 + (function Od(){return UIm;}\\x28))]();\\r\\n\\t\\t}" ascii
    $s20 = "0;\\r\\n\\t\\tA\\x52t[Hs2 + AFy(Sa\\x30) + (f\\x75\\x6ec\\x74i\\x6fn Ix6(\\x29{return ETx\\x39;}()) +\\x20ZZc8](RJp2, Ya);\\r\\n" ascii

  condition:
    (uint16(0) == 0x200a and (8 of them)
    ) or (all of them)
}