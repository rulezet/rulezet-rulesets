rule _20160921_cda776f6c5cb6eec510c00d5294fbfae_20160921_e072f9d237d6_5693 {
  meta:
    description = "datamaliciousorder - from files 20160921_cda776f6c5cb6eec510c00d5294fbfae.js, 20160921_e072f9d237d6a3b969fa334b2e277a33.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "064df16cff12584bccc68fb79fe80908e6edeb4ccf32c3c0b6a79b8b0424820c"
    hash2       = "6a03793a4e6175c2a80395cdedba1eaf5878722aa36c4cbfae104768ed79890d"

  strings:
    $s1 = ";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ot\";})(),(function fu" ascii
    $s2 = " fuck(){return \"Vf\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Y" ascii
    $s3 = "{return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Jh\";})(" ascii
    $s4 = "eturn \"Ai\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Oh\";})(),(" ascii
    $s5 = "ion fuck(){return \"ADy\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}