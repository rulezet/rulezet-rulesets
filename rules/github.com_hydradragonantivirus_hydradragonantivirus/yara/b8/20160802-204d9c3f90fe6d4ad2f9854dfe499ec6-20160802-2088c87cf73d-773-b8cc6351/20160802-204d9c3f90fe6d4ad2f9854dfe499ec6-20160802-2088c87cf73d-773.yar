rule _20160802_204d9c3f90fe6d4ad2f9854dfe499ec6_20160802_2088c87cf73d_773 {
  meta:
    description = "datamaliciousorder - from files 20160802_204d9c3f90fe6d4ad2f9854dfe499ec6.js, 20160802_2088c87cf73d0baca2a3898b1ea3b63a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6fe07d7e2f3260c61a89615d7e360af426c81d62a56e8367d20a398f741ee6d"
    hash2       = "6108a088df01ad746e7410162c78158e92e9213a1c36d45b698f27a13d5324a4"

  strings:
    $s1 = "\";\\x0d\\n\\x76ar Uh6 = \"len\"\\x20+ \"\\x22\\x3b\\r\\nfunct\\x69o\\x6e\\x20KEx3(TEw){return TEw;};va\\x72 Aa9 = \\x22GET\" " ascii
    $s2 = "\";\\r\\nvar Dr\\x20= \"Creat\" + \"\";\\r\\nvar ZFt = \"gth\" + \"\";\\r\\n\\x76\\x61r \\x42v8 = \"\\x6cen\" + \"\";\\r\\nfunct" ascii
    $s3 = "6unct\\x69on STv\\x30(Ra0){return Ra0;};var \\x54Vr\\x33 \\x3d \"e\" + \"\";\\r\\nvar\\x20VTk0 = \\x22wri\\x74\" + \"\\x22;\\r" ascii
    $s4 = "22ream\" + \"\";\\r\\n\\x76ar Yv\\x20= \"St\" + \\x22\";\\r\\nvar\\x20XOs = \"DB.\\x22 + \"\";\\x0d\\nf\\x75nction \\x56w3(NAa){" ascii
    $s5 = "e\" \\x2b \"\";\\r\\nvar \\x4aW\\x7a3 =\\x20\"n\" + \\x22\";\\x0d\\n\\x76ar APp7 = \"ope\" + \"\";\\r\\n\\x66unction Xp6(Ik){ret" ascii
    $s6 = "+ \"\";\\r\\nfunction DEk\\x30(Ja\\x29{return Ja;};functio\\x6e \\x50J\\x68(M\\x54j4){r\\x65turn\\x20MTj4;};var\\x20RVy = \"e\" " ascii

  condition:
    (uint16(0) == 0x200a and (all of them)
    ) or (all of them)
}