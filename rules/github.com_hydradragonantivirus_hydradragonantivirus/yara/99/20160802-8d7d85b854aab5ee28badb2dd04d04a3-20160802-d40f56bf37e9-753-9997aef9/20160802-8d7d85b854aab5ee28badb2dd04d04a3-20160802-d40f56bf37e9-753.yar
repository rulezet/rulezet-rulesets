rule _20160802_8d7d85b854aab5ee28badb2dd04d04a3_20160802_d40f56bf37e9_753 {
  meta:
    description = "datamaliciousorder - from files 20160802_8d7d85b854aab5ee28badb2dd04d04a3.js, 20160802_d40f56bf37e9d66e760f3951be6a1688.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e2e8e9597bb946273d7bf35ec6e91e8a8692847eaae6cd9f1e45a5641d72c5b"
    hash2       = "afe30349d236f2a951130b30e38d82dc39adc51ccdb203c2379f399980926980"

  strings:
    $s1 = "3b\\r\\x0avar Uh6 = \"len\\x22 + \\x22\\x22;\\r\\nfunc\\x74i\\x6f\\x6e KEx3(TEw){return TEw;};v\\x61r GAa9 \\x3d \"GET\\x22 + \"" ascii
    $s2 = "\\nvar Hp4\\x20=\\x20\"he\" + \"\";\\r\\nv\\x61r Qy3 = \"pt\\x2eS\" + \"\";\\r\\nvar PXo9 = \"W\\x53cri\" + \"\";\\r\\nfunction " ascii
    $s3 = "ream\" + \"\";\\r\\x0avar Y\\x76 = \"St\" +\\x20\"\";\\r\\nva\\x72 XOs = \"DB\\x2e\" + \"\"\\x3b\\r\\n\\x66unction\\x20Vw3(NAa){" ascii
    $s4 = "2\";\\x0d\\nvar Qx = \"\\x45MP\" + \"\";\\r\\nvar\\x20Mq2 = \"%T\" \\x2b \"\";\\r\\n\\x66unction BZb(YSa){return Y\\x53a;};var W" ascii
    $s5 = "\" + \"\";\\r\\nfunction DE\\x6b0(J\\x61){return Ja;};functi\\x6fn\\x20P\\x4ah(\\x4dTj4){\\x72etur\\x6e MTj4;};va\\x72 RVy = \"e" ascii
    $s6 = "unction \\x55p\\x28Wr\\x36){return Wr6;}\\x3bvar AH\\x61 = \"bject\" + \"\";\\r\\nv\\x61\\x72 GC\\x6f = \"te\\x4f\\x22 + \"\";" ascii
    $s7 = "unc\\x74ion ST\\x760(Ra0){return Ra0;};var\\x20TV\\x723\\x20= \"e\" + \"\";\\r\\nva\\x72 VTk0 =\\x20\"wr\\x69t\" + \\x22\";\\r" ascii

  condition:
    (uint16(0) == 0x200a and (all of them)
    ) or (all of them)
}