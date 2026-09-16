rule _20160921_164a257da283d5c859dcaffb21bf752c_20160921_56567a449e5a_4495 {
  meta:
    description = "datamaliciousorder - from files 20160921_164a257da283d5c859dcaffb21bf752c.js, 20160921_56567a449e5ae44cd4a4e62bb55e63f3.js, 20160921_a0b892850e7511a70b7c95d4603de0d8.js, 20160921_c07f026b9458324f489ec08b7859e758.js, 20160921_fb2ccc1a635114bc23ea8a0a8413b110.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36edb416a5f8703ead3fb8f8fbb7a0fb98ac21c559eb20558b33460ba9dfc9a0"
    hash2       = "e0950a0ccf96b116ed17c3fbaa99325e34f0b717e3e354bd1f926eee8465c6a7"
    hash3       = "0b5459eb728a278a131a764184d1d333fcd3fc212087b66d9cedce792b1a2d7a"
    hash4       = "ea2be3685bc68d327f9689a9fc4de597314db751f1eacc3ff5fbee0dd0397db0"
    hash5       = "c85e7d8e5c1682f21f2d8c9a0e1f6039d583d7eda8276ca9ed3ed381fbde9a7e"

  strings:
    $s1 = "k(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";" ascii
    $s2 = "n fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"" ascii
    $s3 = "k(){return \"IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"NKq\"" ascii
    $s4 = "turn \"LGo\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"USf\";})()," ascii
    $s5 = "return \"USf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}