rule _20160921_04e35734989b05b680234592aacc01ad_20160921_2b890152a974_3224 {
  meta:
    description = "datamaliciousorder - from files 20160921_04e35734989b05b680234592aacc01ad.js, 20160921_2b890152a974503e2dcd034f2b4084b0.js, 20160921_4e6afd7ea6614e65fabdc4281ed92b34.js, 20160921_f926399cbb634492c58e195c86a0bbde.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6553e0c768ddf3ba1bc09a83e90e280707f7613c13bcc2b4bae89c9a347ee2f5"
    hash2       = "74075b371da5cc0281ecbcdc311542bcafb1a5daba17f8b3fafc81a88714f625"
    hash3       = "2af9fdbe6325bb563ca12f506f0bc07133a1951c94c5f0bd5dced26a493d8e18"
    hash4       = "15b29ae0204a4b512f15931b197f4e0ddaad99fc24c68356f1631bedc62dcac6"

  strings:
    $s1 = "(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IRn\";" ascii
    $s2 = "unction fuck(){return \"RAi\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){re" ascii
    $s3 = "eturn \"UXf\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Wo\";})()," ascii
    $s4 = "(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"OPz\";})(),(function fuck(" ascii
    $s5 = "nction fuck(){return \"FJs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){ret" ascii
    $s6 = ";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"MIl\";})(),(function fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}