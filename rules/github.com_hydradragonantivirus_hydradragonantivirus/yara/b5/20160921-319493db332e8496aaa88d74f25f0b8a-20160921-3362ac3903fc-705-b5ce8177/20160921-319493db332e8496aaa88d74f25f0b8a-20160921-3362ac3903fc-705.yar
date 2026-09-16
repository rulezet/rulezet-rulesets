rule _20160921_319493db332e8496aaa88d74f25f0b8a_20160921_3362ac3903fc_705 {
  meta:
    description = "datamaliciousorder - from files 20160921_319493db332e8496aaa88d74f25f0b8a.js, 20160921_3362ac3903fc5c5d2da5d44e3afe884a.js, 20160921_4aeb02b393c6ed3fdeadcb6a29499bfc.js, 20160921_4b85b9629682d9cbd379b3404bd09eb1.js, 20160921_702e8529103b960a902ddb030da0de45.js, 20160921_8471da3d602dedb9a4749d6e2c757b47.js, 20160921_9ed8ba5d12b4be06b54bbeb7c9325180.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0c9f735bec8627a5cf19b6426c972080cd36752f67aea5abb70a9217297a2e1"
    hash2       = "923e3ebc3e8bab3120c507f019cac28dec05009a69ab441bfb8be6f7f1a4d258"
    hash3       = "8899077a1617372e22229a59750fc04d1c9a0b2a1176b97742c5d76576a2edb1"
    hash4       = "43de7c579d15cb70a31da759a94145ff9a831b9bf0e5ff93ae38b5064231b62f"
    hash5       = "cf8ba9fdbe4ef225cb892f7294538710b1dd7e8bc4e280897680c51e03816d1c"
    hash6       = "98a5a561c128a716a07f6503ae8144cb9404c06eb1a2796af84924653c81967c"
    hash7       = "19b8471b5bf67286e6bfe340e23abef1def848daa18c886f2eddc2eeaa160df7"

  strings:
    $s1  = "{return \"DAp\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Wy\";})" ascii
    $s2  = "{return \"KIc\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"UEg\";})" ascii
    $s3  = "})(),(function f000(){return \"Br\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"MOc\";})(),(function f00" ascii
    $s4  = "urn \"Tn\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"YTp\";})(),(" ascii
    $s5  = "{return \"MBb\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(" ascii
    $s6  = "{return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Br\";})()" ascii
    $s7  = "tion f000(){return \"Fs\";})(),(function f000(){return \"KIc\";})(),(function f000(){return \"KIc\";})(),(function f000(){return" ascii
    $s8  = "rn \"DYx\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Br\";})(),(fu" ascii
    $s9  = "turn \"ZFe\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})()," ascii
    $s10 = "){return \"PTi\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";}" ascii
    $s11 = "n f000(){return \"RLk\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"" ascii
    $s12 = "function f000(){return \"IAa\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Lp\";})(),(function f000(){re" ascii
    $s13 = " f000(){return \"BQb\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"K" ascii
    $s14 = "n \"DYs\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"HJm\";})(),(fu" ascii
    $s15 = " f000(){return \"MJq\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"" ascii
    $s16 = "eturn \"Vj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s17 = "ion f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Br\";})(),(function f000(){return " ascii
    $s18 = " \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"NBs\";})(),(fun" ascii
    $s19 = "n f000(){return \"ZIi\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"NBs\";})(),(function f000(){return " ascii
    $s20 = "tion f000(){return \"Uo\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Uo\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}