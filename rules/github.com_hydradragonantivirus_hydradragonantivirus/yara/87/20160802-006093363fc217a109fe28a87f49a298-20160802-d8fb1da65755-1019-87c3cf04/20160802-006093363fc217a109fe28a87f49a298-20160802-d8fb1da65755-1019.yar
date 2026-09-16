rule _20160802_006093363fc217a109fe28a87f49a298_20160802_d8fb1da65755_1019 {
  meta:
    description = "datamaliciousorder - from files 20160802_006093363fc217a109fe28a87f49a298.js, 20160802_d8fb1da65755dba5f14fafc3ece936ea.js, 20160802_f81dcd2e4ccf29d4f72865bc517e70dd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7fe598a7816fea7f5214b3dc157aa7f195d7922f31bad2cf0059458a09a04ce8"
    hash2       = "5528151b0b0d257ec725a013e136811d87d86b95b4b80a7fe9de1f9138670c41"
    hash3       = "2c5be82caa1930b2811cfdd486951cdaf838eb07c16420637fc5fa0f5506835b"

  strings:
    $s1 = "2;\\x0d\\nvar Uh6 = \"le\\x6e\" +\\x20\\x22\";\\r\\nfun\\x63t\\x69\\x6fn KEx3(TEw){return TEw;};\\x76ar Aa9 \\x3d \"GET\\x22 + " ascii
    $s2 = "nfun\\x63tion S\\x54v0(Ra0){return Ra0;};va\\x72 T\\x56r\\x33 = \"e\" + \"\";\\r\\nv\\x61r VTk0 \\x3d \"w\\x72it\" +\\x20\"\";" ascii
    $s3 = "nvar \\x44r = \"Creat\" + \"\";\\r\\nvar ZFt = \"gth\" + \"\";\\x0d\\x0ava\\x72 Bv8 =\\x20\"len\" + \"\";\\r\\nfunction Zk(KHz9)" ascii
    $s4 = " + \"\";\\r\\nfunction DEk\\x30(Ja\\x30){return Ja0;};funct\\x69o\\x6e \\x50Jh\\x28MTj4)\\x7bretu\\x72n MTj4;};v\\x61r RVy = \"e" ascii
    $s5 = " \"ream\" + \"\";\\x0d\\nvar \\x59v = \"St\" \\x2b \"\";\\r\\nv\\x61r XOs = \"D\\x42.\" + \"\\x22;\\r\\x0afunctio\\x6e Vw3(NAa){" ascii

  condition:
    (uint16(0) == 0x200a and (all of them)
    ) or (all of them)
}