rule _20160802_4399188ed594370582c1084e6e4779ad_20160802_ee6100ee02ad_470 {
  meta:
    description = "datamaliciousorder - from files 20160802_4399188ed594370582c1084e6e4779ad.js, 20160802_ee6100ee02ad1c1831e87e0806bda434.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db40dec56ca07444b1a83db9e9890a41db566bb7ce80c245384ce90840594f01"
    hash2       = "3fc041a7fb1e8e824c17cf58ba1c82d1a95351f72aec22730e7e93b33b98edc5"

  strings:
    $s1  = "ti\\x6eue;\\r\\n\\t\\t}\\r\\n\\t\\t\\r\\n\\t\\tvar ARt=WScript[RJe4 + LFp + (function \\x43Yi(){return As3;\\x7d()) + (function " ascii
    $s2  = "j2+Xs5 + L\\x713+Wc+(function Ii(){ret\\x75rn N\\x4cs;}()) + \\x52Gl2+Hh+IVm];\\r\\nvar Ba5=WScript[RJe4 + LFp + As3 +\\x20(fun" ascii
    $s3  = "0x100000000;\\r\\n}\\r\\nreturn (n >>> 0) * 2.32\\x38306436538696\\x33e-10;\\r\\n} el\\x73e n =\\x20\\x30xefc8249d;\\r\\n};\\r" ascii
    $s4  = " 1\\x3768863\\x20* s[p\\x5d + c * 2.328\\x33064365386\\x3963e-10;\\r\\nr\\x65turn\\x20\\x73[p] = t - (\\x63\\x20= t | 0);\\r\\n}" ascii
    $s5  = "n\\tca'+''+'tch (e) {WScript[S\\x44b + IDo]\\x2810\\x300); continue;};\\r\\n} while (\\x55z);\\r\\n\\r\\nW\\x53c\\x72\\x69pt.Qui" ascii
    $s6  = "\\x20\\x52e1(){retu\\x72\\x6e RJe\\x34;}(\\x29) + (funct\\x69on \\x4dh(){return LFp;}()\\x29 + As3 + Zu](Pe[OPj]);\\r\\n\\t\\tbr" ascii
    $s7  = "\\r\\nvar E\\x703 = \"43\" + \"\\x22;\\x0d\\nvar Vh = \"th\" + \"\";\\x0d\\nva\\x72 WKb = \"leng\" + \"\";\\x0d\\nfunction Su\\x" ascii
    $s8  = "RCn=RJp2 +\\x20IFj0 + USw;\\r\\n\\r\\nfunction uheprng() {return (function\\x28)\\x20{\\r\\n\\x76ar o\\x20= 48, c = 1, p \\x3d o" ascii
    $s9  = "va\\x72 \\x42Ss4 =\\x20\"1123\" + \"\";\\r\\nva\\x72 Mz9=\\x28BSs4 + If(\\x4bg\\x29, \\x4al9 + CZy + IIk2 + (function NK\\x790()" ascii
    $s10 = "tion Ry0(){return Qq;}\\x28))+NAm9+MSc5 + QRy5+RTo2(\\x4cr8)+Un\\x2bCl8+Ae, Y\\x791 + Ri5+(function\\x20Xl2(){return Dt6;\\x7d" ascii
    $s11 = "aSf)\\x3b\\x0d\\x0a\\x76a\\x72 \\x52J\\x702=Mz + \\x52Gn +\\x20Rh1 + Jl\\x28DTv\\x29 + (function G\\x4fk(){return LVd;}()\\x29 +" ascii
    $s12 = " ERb[QS\\x63 +\\x20\\x4fXv9]],\\x20fa\\x6cse)\\x3b\\r\\n\\t\\t\\tSy[LEs7 + (function Od(){\\x72eturn UIm;}())]();\\x0d\\n\\t\\t}" ascii
    $s13 = "0d\\n}\\r\\n\\r\\n\\x76a\\x72 \\x50e=[\\x5aAe + PAn + Bv7 +\\x20A\\x77 \\x2b Kf6 + Lf7 + Bq1 + \\x47Wy + Xx4 +\\x20NId1, (functi" ascii
    $s14 = "cti\\x6fn Zq9(\\x29{return \\x4el;}())+Wn1+RWi+Po\\x2bCy5 + Nn5+(function GNn(){return FYs1;}()\\x29+R\\x6a3(Sj5)\\x2c\\x20WSb0+" ascii
    $s15 = ") {break;};\\t\\t\\r\\n\\t\\t\\r\\n\\t\\tBa5[ILh6 + Et1]\\x28RCn + (funct\\x69on JYj5(){ret\\x75rn IDj;}()) + Oj9);\\r\\n\\t\\tb" ascii
    $s16 = " \\x57c6(){return Z\\x75;}())](Ot8 +\\x20DWb8 + SSq);\\r\\nv\\x61r Mz\\x3dBa\\x35.ExpandEn\\x76\\x69ronmentStrings(\\x4a\\x6e9(P" ascii
    $s17 = "+ \"\";\\x0d\\nvar CZy = \"ll\" + \"\";\\r\\nvar Jl9 = \"lllll\"\\x20+ \"\";\\r\\nfunctio\\x6e If(YBe){return YBe;};var Kg =\\x2" ascii
    $s18 = "2andom =\\x20function( range )\\x20\\x7b\\x0d\\nretu\\x72n Ma\\x74h.f\\x6coor(range * (rawprng() + (ra\\x77prn\\x67() * 0x200000" ascii
    $s19 = "r\\nvar Id\\x3d\\x4eVd[QSc + OXv9];\\r\\nvar Pe0=(Dv3 + KJd\\x20\\x2b (\\x66unction IMn(){return CZ\\x698;}()), Zs5 + Te1 +\\x20" ascii
    $s20 = "x29 + Xt6);\\r\\nvar UWy4=Pe0[QSc +\\x20(function LBy(){retur\\x6e\\x20\\x4fXv9;}())];\\r\\n\\r\\nvar GRx5=1;\\r\\nvar DAe=2;\\r" ascii

  condition:
    (uint16(0) == 0x200a and (8 of them)
    ) or (all of them)
}