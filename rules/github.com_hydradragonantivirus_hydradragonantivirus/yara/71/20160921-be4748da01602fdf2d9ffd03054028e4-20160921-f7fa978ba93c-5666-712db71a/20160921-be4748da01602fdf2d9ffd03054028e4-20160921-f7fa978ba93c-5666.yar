rule _20160921_be4748da01602fdf2d9ffd03054028e4_20160921_f7fa978ba93c_5666 {
  meta:
    description = "datamaliciousorder - from files 20160921_be4748da01602fdf2d9ffd03054028e4.js, 20160921_f7fa978ba93ca4504da33fc02cbf7f53.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4847889a558b3e0b60d671ec5082e36330f771c8789f9ae89683bf49e7128616"
    hash2       = "8c8d20603b0870465254e9f226f52f020b5b1d986c61571e7a3097b32ea728e0"

  strings:
    $s1 = "tion fuck(){return \"Vb\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return" ascii
    $s2 = "turn \"LGo\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})()," ascii
    $s3 = ")(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Jg\";})(),(function fuck()" ascii
    $s4 = "eturn \"Vb\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})()," ascii
    $s5 = "eturn \"RAi\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}