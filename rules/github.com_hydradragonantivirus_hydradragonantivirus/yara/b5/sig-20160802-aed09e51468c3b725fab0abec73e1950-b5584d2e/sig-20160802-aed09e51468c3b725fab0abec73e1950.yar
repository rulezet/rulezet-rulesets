rule sig_20160802_aed09e51468c3b725fab0abec73e1950 {
  meta:
    description = "datamaliciousorder - file 20160802_aed09e51468c3b725fab0abec73e1950.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5e452e4ef5c35362539b4f002a125cc97c620ed12a2bc3bdfa6c42438f6e886"

  strings:
    $x1  = "    var aAKj = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "x3b\\r\\n\\t\\x09}\\r\\n\\t\\t\\r\\n\\t\\tvar\\x20ARt=WScript[Jm + Fe + JHu8 + Ot8](Oa4(Ea)+JWz3+Tv6+Ep +\\x20Li4 + (function " ascii
    $s3  = "''+'unction Tf2(Hg0){return Hg0;}\\x3bvar\\x20FFm = \"GET\\x22 \\x2b \"\\x22;\\r\\nvar\\x20Hp0 = \\x22n\"\\x20+ \"\";\\r\\nvar E" ascii
    $s4  = "\\r\\nva\\x72 Wv = \"EFGHI\" + \"\";\\x0d\\nvar XPd9 = \"ABCD\" + \"\";\\r\\nvar Xr4 = \"xe\" \\x2b\\x20\"\\x22;\\r\\nfunc\\x74i" ascii
    $s5  = "\\nreturn Math\\x2efloor(range * (\\x72awprng() \\x2b (rawprng() * 0x200000 | \\x30)\\x20* 1.11022302\\x346251565e-1'+''+'6)\\x2" ascii
    $s6  = "BCg){return BCg;};v\\x61r P\\x4ah = \"ose\" + \"\";\\r\\nvar\\x20N\\x41e\\x30 =\\x20\"cl\" \\x2b \"\";\\x0d\\nfunction \\x52Vy(M" ascii
    $s7  = "5\" + \"\";\\r\\nfunction KEx3(TEw){retur\\x6e TEw\\x3b};function OHs\\x30\\x28Lo){r\\x65t\\x75rn Lo\\x3b};var Ly0 = \"p\" + \"" ascii
    $s8  = "turn SHv4;};var Xt6 = \"ll\" + \\x22\";\\x0d\\nvar MSl = \\x22ll\"\\x20\\x2b \"\";\\r\\nvar Te1\\x20= \\x22lllll\" + \"\";\\r\\n" ascii
    $s9  = "n\\t\\r\\n\\tvar \\x48Fz=ne\\x77 Array();\\r\\n\\tf\\x6fr (va\\x72 OP\\x6a=693\\x38 -\\x206938; OPj < Tf0\\x5bJ\\x51u(QSc)\\x20+" ascii
    $s10 = "x59\\x79;}\\x28)) + Gx0](Sy[(func\\x74i\\x6fn Xz3(){return Qa;}\\x28)) + H\\x73\\x32 +\\x20Sa0]);\\x0d\\n\\t\\tAR\\x74[P\\x43l +" ascii
    $s11 = " +\\x20OXv9]], false);\\r\\n\\t\\t\\tSy[\\x28fu\\x6e\\x63tion G\\x692(\\x29{re\\x74urn Mf;}()) + MVd1]();\\r\\n\\t\\t}\\r\\n\\t" ascii
    $s12 = " 2.328306436538\\x36963e-1\\x30;\\x0d\\n\\x7d el\\x73e n = 0xefc8249d\\x3b\\r\\x0a}\\x3b\\r\\nreturn mash;\\r\\n}\\r\\n\\x0d\\nv" ascii
    $s13 = "nvar Ya=3607 \\x2d 360\\x35;\\r\\nva\\x72 UMc=\"\\x3437\";\\r\\n\\r\\nvar ERb=[SUf'+''+'\\x32+Kx2 + (function Fb(){return \\x45i" ascii
    $s14 = "8\\x66unction\\x20Ry0(){return Qq;}())+NAm\\x39, MSc5 + QRy5+RTo2(Lr8)+U\\x6e+Cl8+A\\x65+Yy1 + Ri\\x35+(function Xl2(){\\x72etur" ascii
    $s15 = "20+ \"\";\\x0d\\nvar BSs4\\x20=\\x20\"1123\\x22 + \"\";\\r\\nvar Mz9=\\x28BSs4 \\x2b If(Kg), J\\x6c9\\x20+ \\x43Zy + IIk2 + (fun" ascii
    $s16 = "7a4(NA\\x650\\x29 + PJh]();\\r\\n  \\x20 return NFc(B\\x77);\\r\\n};\\r\\x0a\\r\\n\\r\\nfunction NFc(T\\x66\\x30)\\r\\n{  \\x20" ascii
    $s17 = "x49Ik2 = \"ll\" + \"\";\\r\\nvar \\x43Zy = \"ll\" + \"\";\\r\\nvar Jl9 = \"lllll\" + \"\";\\x0d\\nfunction If(Y\\x42e){return YB" ascii
    $s18 = "72168;\\x0d\\n\\x76ar Id=NVd[Q\\x53\\x63 + OXv9];\\r\\nvar Pe0=(Dv3 + KJd + (fu\\x6e\\x63ti\\x6fn IMn(){return CZi8;}()\\x29, Zs" ascii
    $s19 = "u(MS\\x6c)\\x20+ Xt\\x36);\\r\\nvar UWy4=Pe0[QSc + (func\\x74ion LBy(){return OXv9\\x3b\\x7d\\x28))];\\r\\n\\r\\nvar GRx5=1;\\r" ascii
    $s20 = "())+Oj\\x32\\x2bXs5 + Lq3, Wc+\\x28function Ii(){return NL\\x73;}()\\x29 + RGl2+H\\x68+UIk+(function VEd(){return Uf;}()) + (fun" ascii

  condition:
    uint16(0) == 0x200a and
    1 of ($x*) and 4 of them
}