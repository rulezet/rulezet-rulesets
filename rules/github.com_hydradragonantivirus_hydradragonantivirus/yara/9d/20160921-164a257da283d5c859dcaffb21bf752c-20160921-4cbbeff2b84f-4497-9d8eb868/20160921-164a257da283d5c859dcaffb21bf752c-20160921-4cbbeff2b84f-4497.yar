rule _20160921_164a257da283d5c859dcaffb21bf752c_20160921_4cbbeff2b84f_4497 {
  meta:
    description = "datamaliciousorder - from files 20160921_164a257da283d5c859dcaffb21bf752c.js, 20160921_4cbbeff2b84f01cc3ab55f4eb29babb2.js, 20160921_4d30edc3a4e3226feee5b6289df9e399.js, 20160921_56567a449e5ae44cd4a4e62bb55e63f3.js, 20160921_a0b892850e7511a70b7c95d4603de0d8.js, 20160921_fb2ccc1a635114bc23ea8a0a8413b110.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36edb416a5f8703ead3fb8f8fbb7a0fb98ac21c559eb20558b33460ba9dfc9a0"
    hash2       = "698c46439ef391a98b04ac1a2759ff8a84b30a9c444a7575c5290eb0aa4b66b9"
    hash3       = "d28b5e72375443a9ef1a43fee185a0e5563672a0764eef4f58a90a27302162ea"
    hash4       = "e0950a0ccf96b116ed17c3fbaa99325e34f0b717e3e354bd1f926eee8465c6a7"
    hash5       = "0b5459eb728a278a131a764184d1d333fcd3fc212087b66d9cedce792b1a2d7a"
    hash6       = "c85e7d8e5c1682f21f2d8c9a0e1f6039d583d7eda8276ca9ed3ed381fbde9a7e"

  strings:
    $s1 = "(function fuck(){return \"Av\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){re" ascii
    $s2 = "nction fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){retu" ascii
    $s3 = "(){return \"DRx\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Hs\";" ascii
    $s4 = "eturn \"DRx\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"DRx\";})(" ascii
    $s5 = "fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Wo" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}