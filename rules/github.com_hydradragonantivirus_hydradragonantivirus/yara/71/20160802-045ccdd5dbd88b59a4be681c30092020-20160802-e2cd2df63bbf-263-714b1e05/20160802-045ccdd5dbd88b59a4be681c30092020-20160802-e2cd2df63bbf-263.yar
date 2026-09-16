rule _20160802_045ccdd5dbd88b59a4be681c30092020_20160802_e2cd2df63bbf_263 {
  meta:
    description = "datamaliciousorder - from files 20160802_045ccdd5dbd88b59a4be681c30092020.js, 20160802_e2cd2df63bbfe4d2edd3d02a2e675089.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "07e7c340fe79614b9a4c22e30a6502f370de6b1ff5b92a4680a9130783659059"
    hash2       = "33552b5ea8d99ab5e6cb5217e9ba2c5bf5489b313dab33688d8023c9e518a4d5"

  strings:
    $s1  = "\\r\\nh -= n;\\r\\nn += h * 0x100000000;\\r\\n}\\r\\nretu\\x72n (n >>> 0) \\x2a 2.32830643\\x3653869\\x36\\x33e-10;\\r\\n} else " ascii
    $s2  = "c\\x6fntinue;}'+''+';\\r\\n} while (Uz);\\r\\n\\x0d\\nWScript\\x2eQu\\x69t(0);\\r\\n\\r\\nfunction BKw(DHf1\\x20/* k  */\\x29\\r" ascii
    $s3  = ";\\r\\n\\t\\t}\\r\\n\\x09\\t\\r\\n\\t\\tvar ARt=WScript[(function Wc(){return ZOc9;}()) + \\x57c6 + DAz1](TYj+M\\x66(Cc0)+Wt6+XO" ascii
    $s4  = "Gl2(){return\\x20Gr4;}()) + (function Ii\\x28){re\\x74urn TEd;}\\x28)) + Zf+Hh+VUg + RUf+Cp + IHt];\\r\\nvar Ba5=WScript\\x5bNMh" ascii
    $s5  = "x28funct\\x69on LBy\\x28){return OXv9;}())];'+''+'\\x0d\\n\\r\\nvar GRx5=1;\\r\\nvar DAe=2;\\r\\nv\\x61r\\x20Ya=360\\x37 - \\x33" ascii
    $s6  = "7we\" + \"\";\\r\\nfu\\x6ection RTo2(Xh\\x31){return Xh1;};var Lr8 =\\x20\".inf\\x22 \\x2b \"\";\\r\\n\\x76ar QRy5 = \\x22\\x72d" ascii
    $s7  = "t1\\x5d(R\\x43n + (function JYj5(){return IDj;}()) + Oj9\\x29;\\r\\n\\t\\tbreak;\\r\\x0a\\t}\\r\\n\\tcatch (e\\x29 {WScript[SDb " ascii
    $s8  = "\\n\\x66unction Rj3(TXh){return TXh;};var\\x20QSj5 = \"j\" + \"\";\\r\\nvar GNn \\x3d \"\\x68h\" + \"\";\\r\\nvar UAm\\x38 = \"g" ascii
    $s9  = "\\r\\nfunction TN\\x6b4(Xs5){return Xs\\x35;};var Xl\\x32 = \\x22an\" + \"\";\\r\\nvar MHr = \"/\\x73\\x22 + \"\";\\r\\nva\\x72 " ascii
    $s10 = ";\\r\\x0avar Pe0=(Dv3 + KJd + (functi\\x6fn IMn(){return CZi8;}\\x28\\x29\\x29, Zs5 + Te1 + Su(MSl) + Xt6);\\r\\nvar UWy4=Pe0[Q" ascii
    $s11 = "No;}\\r\\n\\t\\te\\x6cse \\r\\n\\t\\t\\t{EFq7=\\x50a\\x37[EN\\x6f];}\\r\\n\\t\\tDq.push(String[Kt\\x20+ Fd + XUw +\\x20Eo6](EFq7" ascii
    $s12 = "x0amash = \\x6eull;\\r\\nvar random \\x3d\\x20\\x66uncti\\x6fn( r\\x61nge\\x20) {\\r\\nreturn Math.floor(range\\x20* (\\x72awprn" ascii
    $s13 = "b[QSc + OXv9]],\\x20fa\\x6c\\x73e);\\r\\n\\t\\x09\\tS\\x79[LE\\x737 + (function Od(){return UIm;\\x7d())]();\\r\\n\\t\\t}\\r\\n" ascii
    $s14 = "h(Yd6){return Y\\x646\\x3b};\\x66unction Up(Wr6\\x29{retur\\x6e Wr6;};var DAz1 = \"\\x62\\x6aect\\x22 + \"\";\\x0d\\x0avar Wc6 =" ascii
    $s15 = "r PI\\x7a0 \\x3d \"%/\" + \"\";\\x0d\\nvar MBi = \"MP\\x22 + \"\";\\r\\nvar\\x20Ft = \"\\x25TE\" + \"\";\\r\\nfunction Rn(YD\\x7" ascii
    $s16 = "on Ix6\\x28){return ETx9;\\x7d()) + \\x5a\\x5ac\\x38]\\x28RJp2, \\x59a);\\r\\n\\t\\tARt[\\x44Ek0(KCh\\x35) + TZa + PJh(RVy)]\\x2" ascii
    $s17 = "OPj=0\\x3b \\x4f\\x50j < \\x50\\x65[Q\\x53c + (function FT\\x6a(){return OXv9\\x3b}())]; OPj\\x2b+)\\r\\n{\\r\\n\\t\\x74ry \\x0d" ascii
    $s18 = " Ly(DH\\x661 /* k  */)\\r\\n{\\r\\n \\x20 \\x20var Pa7=ne\\x77 Array();\\r\\n\\t\\r\\nPa7[\\x3128]=1\\x399;\\r\\nPa7[129]\\x3d" ascii
    $s19 = "unction Ry0(){return Og6\\x3b}())+NAm9+MSc5 + QRy5+RTo\\x32(Lr8)+\\x55n+WRr1 + \\x5ax, SUf2+QEw+MHr +\\x20TNk4(Xl2)+(functi\\x6f" ascii
    $s20 = "09\\t}\\r\\n\\t\\ttry\\x0d\\n\\t\\t{\\r\\n\\t\\t\\x09Vg8(RCn, HFz);\\r\\n\\t\\t} \\r\\n\\t\\t\\x63atch (e) {break;};\\t\\t\\r\\n" ascii

  condition:
    (uint16(0) == 0x200a and (8 of them)
    ) or (all of them)
}