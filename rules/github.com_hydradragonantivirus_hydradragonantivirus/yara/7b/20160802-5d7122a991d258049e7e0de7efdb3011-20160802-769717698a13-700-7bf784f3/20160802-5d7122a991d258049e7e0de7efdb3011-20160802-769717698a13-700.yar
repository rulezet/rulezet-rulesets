rule _20160802_5d7122a991d258049e7e0de7efdb3011_20160802_769717698a13_700 {
  meta:
    description = "datamaliciousorder - from files 20160802_5d7122a991d258049e7e0de7efdb3011.js, 20160802_769717698a13a80a36898984b8207cf4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62b2ad099d086538accae196f54756cd8044e226e4af98b24c47524661a8962a"
    hash2       = "765c6104846a334b88ba6e7e14d6edcdd8c6cb478d8540b1203d472e07ed4071"

  strings:
    $s1 = "3d \"\\x63l\" + \"'+''+'\\x22;\\r\\nfun\\x63\\x74ion WPa(Vk){return Vk;};var BLy1\\x20\\x3d \"Text\" + \"\";\\r\\nvar TNr1 =\\x2" ascii
    $s2 = "\\x4fb\\x6a\"\\x20+ \"\\x22;\\r\\n\\x76ar Ni = \"Creat\" + \"\";\\r\\x0avar \\x52\\x719 = \"join\" + \"\\x22;\\r\\x0afu\\x6ectio" ascii
    $s3 = "WXb =\\x20\"en\" + \"\";\\r\\nvar \\x43b2 = \"o\\x70\" +\\x20\"\"\\x3b\\r\\nfunc\\x74i\\x6fn Hf8(FMs){return FMs;}\\x3bvar Jz1 " ascii
    $s4 = "Kt;};functi\\x6fn Tl8(I\\x57s5){return IWs\\x35;};\\x76\\x61r\\x20Jc = \\x22e\" + \"\"\\x3b\\r\\nva\\x72 Oy = \"Cod\" + \"\";\\r" ascii
    $s5 = " Er8;};functi\\x6fn R\\x56y(Mb0){return Mb0;};\\x76a\\x72 \\x5aVt\\x37 = \"l\\x65\" + \\x22\";\\r\\nvar LW\\x72 = \"oFi\" + \"\"" ascii
    $s6 = "\"\";\\r\\nfunction ORk1(Ds){retur\\x6e Ds;}\\x3bvar Xz4 = \"se\\x22 + \"\";\\r\\nvar Pg\\x33 = \"clo\" + \"\";\\r\\n\\x66uncti" ascii
    $s7 = " \"eT\" + \"\";\\r\\nvar Fy = \"Sav\" + \"\";\\r\\nf\\x75nction Nq(\\x4fBj){return \\x4fBj\\x3b};funct\\x69o\\x6e ETx9(ZZc8){re" ascii
    $s8 = "x4cr){return \\x4cr\\x3b};f\\x75nction\\x20Xp\\x36(\\x49k){return Ik;};var Fu3 \\x3d \"O\" + \"\";\\r\\nfunction Vw\\x33(NAa){re" ascii

  condition:
    (uint16(0) == 0x200a and (all of them)
    ) or (all of them)
}