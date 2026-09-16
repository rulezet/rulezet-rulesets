rule _20160919_32badfcb878b3edf80217ab0016fa503_20160919_3383b124c7ed_762 {
  meta:
    description = "datamaliciousorder - from files 20160919_32badfcb878b3edf80217ab0016fa503.js, 20160919_3383b124c7ed149d1bcae61a325c040e.js, 20160919_3457fcdc86cf82f3f48be39fd6d21d4b.js, 20160919_373a556695ea9f4ab0bfcce41192289d.js, 20160919_5264fdb87d35fab70befdb76bdb311cc.js, 20160919_590a040aa1aa19ba0ffd4f0feab6d794.js, 20160919_68c4068c6501167bc75b5a064419430e.js, 20160919_9678ff33aaf7eac1d1fd0d9abb8c214f.js, 20160919_a2d3595a1269e27bdb17ce58e63648e8.js, 20160919_a3f59bcdeee44d30257e4bf6fa4cdcfc.js, 20160919_a765740456e5582fbff2132eb4e78b9a.js, 20160919_b40395b85bcb25f67a4970ed038feb51.js, 20160919_ba17efd1ed858bb9046281e8548ab6a5.js, 20160919_c21ae7018f9274d6fa00a1b7666dfc5e.js, 20160919_c77e9bbd2d0a40f44e82d702c8601ca4.js, 20160919_cc2002be14649bd2541480d454d10ac8.js, 20160919_e1e147508dea812af1e7488b6a8c4c50.js, 20160919_f11001d9bfd1a13a48a48322ea5c69ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59bdfe504cade6d322376d9ff145f88e66be5b4e392d02aefc95b4fd229a27c2"
    hash2       = "bc7f8a123689dbd175618525e539db6d88e43732d35e66641b3c7101d09cebf8"
    hash3       = "97f649d59e321a2061dc4606bf99d368289ab15b7da34d8d6cae1455d50a5f9b"
    hash4       = "0015b2d7a944cfd9b848c15149993048aecc0416492dc497acdb86baf328e3f1"
    hash5       = "f937a4334b436d16315de77117c96786be39df5ba638c3788227c76e58b07a06"
    hash6       = "f81d67b5dd43561e44b6c6531509f2d99b00dc86a7c25719fe1c3d557d2f0c55"
    hash7       = "c12ad277673b636100c7a027be064fc108c6da20c346a7fa9d5759738b1e36eb"
    hash8       = "b7ba8422d2b027d715e27231d3decafebab66814ac20fb3ad132c47d0d0e2696"
    hash9       = "0b229397b6ce47c6f23765590d433915343b8f4bb263e1653b788687c7bcf0b7"
    hash10      = "e883f2db6b8a68b9451a504a978326d4bb0f8c9b77bf619043591192bc709cc3"
    hash11      = "236542c3b6d70af0aa4c264a9be9cdf588d97e736518371eaef6ca01159dd985"
    hash12      = "bcdaff7a4dd0ea79bcfafe36d714ef6faa170f6c6801ae288203f92fb124219d"
    hash13      = "b06083dc34a1889065081f72969da892d34363674f73007c278175c31d2cc7e8"
    hash14      = "1bc79557512a63d8c2b057af7d479b9d935a629e973821f967368a783a161dd0"
    hash15      = "646501c974e0245ae264797405fcb7c60a679b20a6fa73e0bcabdff024cb1f33"
    hash16      = "628994473d547ea0ebd68cae72cb8bb929a8de193d2a350276807bffb10c75c4"
    hash17      = "06d32cfe33646b92f9c9c914243574293652450a26b1eeef2747d6f389b5eb80"
    hash18      = "cc90de7511a0dbabe20b24e50e08fdb0bf6328d8ebd1a7787dfe35d451586cd9"

  strings:
    $s1  = "\\x6c\";})()]], \"VXy\": [3, [4, (function avast(){return \"\\x6a\";})()]], \"WIi\": [3, [4, (function avast(){return \"\\x6f\";" ascii
    $s2  = "rn \"\\x7c\";})()]], \"JTa\": [3, [4, (function avast(){return \"\\x7b\";})()]], \"Kh\": [3, [4, (function avast(){return \"\\x2" ascii
    $s3  = "]], \"Dq\": [3, [4, (function avast(){return \"\\x28\";})()]], \"Yi\": [3, [4, (function avast(){return \"\\x29\";})()]], \"Ay\"" ascii
    $s4  = ")]], \"Ru\": [3, [4, (function avast(){return \"\\x47\";})()]], \"JWk\": [3, [4, (function avast(){return \"\\x40\";})()]], \"IT" ascii
    $s5  = "n avast(){return \"\\x3a\";})()]], \"Ph\": [3, [4, (function avast(){return \"\\x3c\";})()]], \"JKw\": [3, [4, (function avast()" ascii
    $s6  = "\"\\x2a\";})()]], \"JYs\": [3, [4, (function avast(){return \"5\";})()]], \"Hc\": [3, [4, (function avast(){return \"3\";})()]]," ascii
    $s7  = "urn \"\\x53\";})()]], \"Mt\": [3, [4, (function avast(){return \"\\x52\";})()]], \"Vp\": [3, [4, (function avast(){return \"\\x5" ascii
    $s8  = ": [3, [4, (function avast(){return \"\\x6d\";})()]], \"QFk\": [3, [4, (function avast(){return \"\\x6e\";})()]], \"Hf\": [3, [4," ascii
    $s9  = "{return \"\\x44\";})()]], \"XZg\": [3, [4, (function avast(){return \"\\x45\";})()]], \"GBs\": [3, [4, (function avast(){return " ascii
    $s10 = "return \"\\x43\";})()]], \"Zp\": [3, [4, (function avast(){return \"\\x48\";})()]], \"PNu\": [3, [4, (function avast(){return \"" ascii
    $s11 = "St\": [3, [4, (function avast(){return \"\\x2d\";})()]], \"BYr\": [3, [4, (function avast(){return \"\\x2e\";})()]], \"GGc\": [3" ascii
    $s12 = "tion avast(){return \"\\x2b\";})()]], \"Oq\": [3, [4, (function avast(){return \"\\x2c\";})()]], \"Sn\": [3, [4, (function avast" ascii
    $s13 = "nction avast(){return \"\\x7d\";})()]], \"QEh\": [3, [4, (function avast(){return \"\\x7a\";})()]], \"Vx\": [3, [4, (function av" ascii
    $s14 = " (function avast(){return \"\\x41\";})()]], \"Eb\": [3, [4, (function avast(){return \"\\x42\";})()]], \"CRm\": [3, [4, (functio" ascii
    $s15 = " [4, (function avast(){return \"7\";})()]], \"MAe\": [3, [4, (function avast(){return \"\\x25\";})()]], \"Ym\": [3, [4, (functio" ascii
    $s16 = "tion avast(){return \"\\x58\";})()]], \"UUo\": [3, [4, (function avast(){return \"1\";})()]], \"KNe\": [3, [4, (function avast()" ascii
    $s17 = "x3b\";})()]], \"Pc\": [3, [4, (function avast(){return \"\\x3e\";})()]], \"Uj\": [3, [4, (function avast(){return \"\\x3d\";})()" ascii
    $s18 = "[3, [4, (function avast(){return \"6\";})()]], \"SIk\": [3, [4, (function avast(){return \"8\";})()]], \"Xh\": [3, [4, (function" ascii
    $s19 = "{return \"\\x22\";})()]], \"MLp\": [3, [4, (function avast(){return \"\\x20\";})()]], \"Mf\": [3, [4, (function avast(){return " ascii
    $s20 = "\": [3, [4, (function avast(){return \"\\x4b\";})()]], \"WTd\": [3, [4, (function avast(){return \"\\x4c\";})()]], \"Yn\": [3, [" ascii

  condition:
    (uint16(0) == 0x0a0a and (8 of them)
    ) or (all of them)
}