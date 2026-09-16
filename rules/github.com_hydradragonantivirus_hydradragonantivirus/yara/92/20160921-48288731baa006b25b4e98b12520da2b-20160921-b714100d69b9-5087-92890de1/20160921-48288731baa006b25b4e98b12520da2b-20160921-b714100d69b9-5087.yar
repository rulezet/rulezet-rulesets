rule _20160921_48288731baa006b25b4e98b12520da2b_20160921_b714100d69b9_5087 {
  meta:
    description = "datamaliciousorder - from files 20160921_48288731baa006b25b4e98b12520da2b.js, 20160921_b714100d69b955de920a302ff8bef7db.js, 20160921_e07d4e2b80172d933515ba35e18c07eb.js, 20160921_ee80dc6199fa2bd2aea50402a233f984.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce917015afcf31459cc47b8864f85394a756701f6338f6a2cbe079779c3ecd43"
    hash2       = "fc43d54db3c24d6f7ce2d47a45ffcd0768d5cfe90e405322e477be98fe4a8170"
    hash3       = "d93efcba4ba3ef570f21adda2cc5413ab9ed3865a53a97ad1e05113ebc7c4787"
    hash4       = "b51d9165093e08385081a749ef6331a3556fe2739b6c8f85b62e7f6ec1b4f662"

  strings:
    $s1 = "ion fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"" ascii
    $s2 = "on fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"" ascii
    $s3 = "ck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\"" ascii
    $s4 = " fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"J" ascii
    $s5 = "){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Vb\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}