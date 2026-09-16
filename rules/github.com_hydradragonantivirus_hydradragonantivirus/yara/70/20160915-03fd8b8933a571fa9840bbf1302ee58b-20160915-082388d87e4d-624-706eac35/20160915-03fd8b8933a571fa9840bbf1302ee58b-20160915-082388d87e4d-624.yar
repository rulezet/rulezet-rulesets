rule _20160915_03fd8b8933a571fa9840bbf1302ee58b_20160915_082388d87e4d_624 {
  meta:
    description = "datamaliciousorder - from files 20160915_03fd8b8933a571fa9840bbf1302ee58b.js, 20160915_082388d87e4d80ea85df8c1c19d0399a.js, 20160915_1c69a3c162d0f59e52c9fc1b1712f8e5.js, 20160915_1d37253497e0b553f44cf56602891e53.js, 20160915_2107804441db8b31b5753e64506b1986.js, 20160915_30fd1a0aa7529a8d0f23ff4f64d7b7c8.js, 20160915_316de430b82a04d79cfb297a5f49fe5f.js, 20160915_480162906212dbcb707520c635db1e98.js, 20160915_4b49dbe895448dca5bc4d3e574b60208.js, 20160915_551f24d632a15664d370bbf2366d357c.js, 20160915_59c72b0cb8287609f57546067180b8f0.js, 20160915_60f32cef8f4d204ed08b6be3acc1a5a1.js, 20160915_627abec7e14306ae66c5edf68f779dc2.js, 20160915_63e2c4eb34195e1b3058a2562b5230ce.js, 20160915_780cc6454b0061df4ff891e88c239abb.js, 20160915_8449879b34882cd2c90a5e79081a6561.js, 20160915_85c97bb2b55d3fd4f72fb33dc393c6ba.js, 20160915_95116a25d43418037fec80c31b0289fe.js, 20160915_a85b9b34786e2a3afbcb2da3c3dcdbfd.js, 20160915_ac2900cb21e8e90975f6b9469e87d7e4.js, 20160915_ac46b25fdd9fbbe23431cd18263d7d1b.js, 20160915_dfacf65321133088d3b1612a871500a8.js, 20160915_e639b9466c2fea20dd9a9ea6a4804f40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8cf70d1cc96130163c2516d635e20b2dd71393d509b9167883628945e77b1fe5"
    hash2       = "3a3baef0b7850a5f9a1c12144a81e57c5087b0ffe43393948e30dfbaee96659c"
    hash3       = "b5de1f3ee57487d705b23c9ea545b798dcb07b9517c2b6abb91163cb32d08fda"
    hash4       = "d45075a248a0a8ae18f80409a4eaa183b0298e1cf34e8676c875344708c23238"
    hash5       = "cb78df4615bf3a0581038806d78e62a55a341472c7776aa70d6d71545a129a48"
    hash6       = "88a9c11fa4e4178c487915e8296d0f4d90008163bbfca368462a6db76e70a040"
    hash7       = "6e7490c32a31c0de9602c19d0405b5cecd822546800dc060a1a3d1f2052a7aff"
    hash8       = "e624dc3daa6bc02deafaf186485589cbeabae974423e926ce3797a2e4d41077f"
    hash9       = "210390c10fcaeed77248181e7d6a12ddb9cbeefd1b76900f059f5b3ec4cb3ac8"
    hash10      = "db15d50c4ef29bf8f24052b8209c103a5bdc46953580afa8229bf64851739236"
    hash11      = "3daaf14b6133526534bac5bea28b2ec2995e4db0589800fa04dd5178354e773c"
    hash12      = "4c319f519776dfa721715e09093f0e62ec4c72c170b5b962e66e8f07a34c260d"
    hash13      = "392f67caeb6d50ea9ca4f9a48da8b85979813285c1b41bbc0e4f00d1741be7cc"
    hash14      = "e239a899e97aca18dee55e25b03bc6eaad49400e1e223f90fced6ad75c9b5b76"
    hash15      = "7eccaa320d2e9f4a299d00855747b2bda2b8af8086fa0b4322241568ee961311"
    hash16      = "53753c9a18a81d170527d678acf7370c5ebbbd3d6f5a8c3b64753f6dc19edd0b"
    hash17      = "5c69d60058d54e66b1daf00a0a30c5ac090e86ba0d6d56d686c4015195330ee4"
    hash18      = "cf8485f1a6a85fd758a83e660d025926d0e97cfa56e35234bbc1804d078f0dad"
    hash19      = "798429f06501664b245dd35151e9cfef77903094e44f69386d9bf16f78ad7dde"
    hash20      = "d6c02c8ffad77735e648ba66a0887f047858f32acf3b29d65a63d54a1404b4c0"
    hash21      = "c7a6ba3ed4423e2455038ea144afeb690f956a3f98266c9f20c8b3890e839719"
    hash22      = "3b9dea114d12efc6b07db1d0717eec49238868f33ac183fd65b67beeaa56c3de"
    hash23      = "911864abdcb63436145101278624dcb243c9d33d535e0857bf89b336b9d4abf7"

  strings:
    $s1  = "()], \"EKn\": [3, (function f(){return \"\\x29\";})()], \"VYh\": [3, (function f(){return \"\\x4d\";})()], \"Of\": [3, (function" ascii
    $s2  = "], \"Jl\": [3, (function f(){return \"\\x0d\";})()], \"Df\": [3, (function f(){return \"\\x09\";})()], \"DEp\": [3, (function f(" ascii
    $s3  = "tion f(){return \"\\x57\";})()], \"Nc0\": [3, (function f(){return \"\\x56\";})()], \"Hr\": [3, (function f(){return \"\\x55\";}" ascii
    $s4  = "\";})()], \"Vx\": [3, (function f(){return \"\\x58\";})()], \"DBk\": [3, (function f(){return \"1\";})()], \"Pe\": [3, (function" ascii
    $s5  = "\"NXi\": [3, (function f(){return \"0\";})()], \"MLz\": [3, (function f(){return \"4\";})()], \"Fa\": [3, (function f(){return " ascii
    $s6  = "0\";})()], \"EEn\": [3, (function f(){return \"\\x41\";})()], \"VMm\": [3, (function f(){return \"\\x42\";})()], \"SHk\": [3, (f" ascii
    $s7  = "7d\";})()], \"Dn\": [3, (function f(){return \"\\x7a\";})()], \"St\": [3, (function f(){return \"\\x7c\";})()], \"Kr\": [3, (fun" ascii
    $s8  = ": [3, (function f(){return \"8\";})()], \"Vl\": [3, (function f(){return \"\\x44\";})()], \"Zy\": [3, (function f(){return \"\\x" ascii
    $s9  = "[3, (function f(){return \"\\x54\";})()], \"Pw\": [3, (function f(){return \"\\x53\";})()], \"Cd\": [3, (function f(){return \"" ascii
    $s10 = "urn \"\\x4a\";})()], \"PBq\": [3, (function f(){return \"\\x4b\";})()], \"GXa\": [3, (function f(){return \"\\x4c\";})()], \"Cz" ascii
    $s11 = "\"WLj\": [3, (function f(){return \"\\x46\";})()], \"Qq0\": [3, (function f(){return \"\\x47\";})()], \"PXx\": [3, (function f()" ascii
    $s12 = "eturn \"\\x43\";})()], \"QQd\": [3, (function f(){return \"\\x48\";})()], \"IVs\": [3, (function f(){return \"\\x49\";})()], \"C" ascii
    $s13 = "\"\\x4e\";})()], \"Jp\": [3, (function f(){return \"\\x4f\";})()], \"Ha\": [3, (function f(){return \"2\";})()], \"Wf\": [3, (fu" ascii
    $s14 = "){return \"\\x6d\";})()], \"KHz\": [3, (function f(){return \"\\x6e\";})()], \"Ao\": [3, (function f(){return \"9\";})()], \"IPa" ascii
    $s15 = "turn \"\\x78\";})()], \"Tb\": [3, (function f(){return \"\\x75\";})()], \"PBp\": [3, (function f(){return \"\\x74\";})()], \"MGt" ascii
    $s16 = " \"LFv\": [3, (function f(){return \"\\x51\";})()], \"By\": [3, (function f(){return \"\\x50\";})()], \"Qq\": [3, (function f(){" ascii
    $s17 = "on f(){return \"\\x77\";})()], \"BNg\": [3, (function f(){return \"\\x76\";})()], \"Hn\": [3, (function f(){return \"\\x71\";})(" ascii
    $s18 = "var COt = {\"Du\": [3, (function f(){return \"\\x6b\";})()], \"FTe\": [3, (function f(){return \"\\x79\";})()], \"Hh\": [3, (fun" ascii

  condition:
    (uint16(0) == 0x0a0a and (8 of them)
    ) or (all of them)
}