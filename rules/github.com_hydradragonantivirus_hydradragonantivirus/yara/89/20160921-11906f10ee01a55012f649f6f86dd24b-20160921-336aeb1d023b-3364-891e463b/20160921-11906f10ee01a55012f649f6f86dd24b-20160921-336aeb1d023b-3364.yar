rule _20160921_11906f10ee01a55012f649f6f86dd24b_20160921_336aeb1d023b_3364 {
  meta:
    description = "datamaliciousorder - from files 20160921_11906f10ee01a55012f649f6f86dd24b.js, 20160921_336aeb1d023bcb845a70471edfe8a8f9.js, 20160921_44880573519212a90b7d910319fc31d8.js, 20160921_4d79e96b422e6679059a17d9524e032c.js, 20160921_5230866e44eda4e054d929933fdfdae1.js, 20160921_5f040a1454cafc62100cb4449da0b7e2.js, 20160921_5fbbbcb8f403a68df153b90d52e5fff9.js, 20160921_67db5ecea174c85a1df44685d8781acd.js, 20160921_783ed6ff0d6e1cf80c95099c29564ec0.js, 20160921_aab5fb25ea8971982ac223655d50aba2.js, 20160921_bad084fc8365d25463811ce32bf91ceb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7e3d843ddea21ba91cad5bd21d3e536f69426d4c4c5a060bbfe7f1f967bda27"
    hash2       = "f77fe3497bb26b47e909d597cb0055c997e8149b22c878594ee85d0303c27381"
    hash3       = "8427ee610833efbf68884e3ec13c4357ae35e1aa0bf8ddc2ffe99b9a7f44fb40"
    hash4       = "d5794a16a28dba8e89768fa9195da33a7e28c3da5fc73a7789e7c04395f23f06"
    hash5       = "4b11d10d6c2a935fa29f47c13ee54d426aac8d667f3bc2f79681ac7e4d365c76"
    hash6       = "0ffb0f3f8e3e8ace2b8b6c1bccf53c8b5a11fd2ed00ff3b54971e8b0ca5e139d"
    hash7       = "1e2661f95b6bb745bac719b1313cfa9a489ecd857f66bfe9fe5398391e372ca4"
    hash8       = "240705f58012306a07f93042172cd93e3bba16b8c9e0a9dd928f169ce059bf22"
    hash9       = "91c59edb0e2a43b5780f865f87a5462b55dab1281045b0a38b38ac155b7d34b6"
    hash10      = "0387ef653c0ac9c5d0aaf638bde80688e7b6b279a435dcab3ff679313abfab3c"
    hash11      = "047a9508e8bdaf65bc39b28d9eac8b287b7a434a3a0808290117a7b71d1d03f6"

  strings:
    $s1 = "on fuck(){return \"Sx\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"" ascii
    $s2 = "\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"ZVi\";})(),(function" ascii
    $s3 = " \"Dc\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Ar\";})(),(func" ascii
    $s4 = "),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Za\";})(),(function fuck(){" ascii
    $s5 = "ction fuck(){return \"IOs\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){retur" ascii
    $s6 = "{return \"Dc\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"UXf\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}