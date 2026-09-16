rule _20160921_099ae50c92fa9b72abe88204de915580_20160921_30a55f1f397a_2676 {
  meta:
    description = "datamaliciousorder - from files 20160921_099ae50c92fa9b72abe88204de915580.js, 20160921_30a55f1f397a54f31c6f0c59c99d921d.js, 20160921_6ae4be616177cbd93c9c15ffb5dcddae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "344e6822e369c3beb064ffee655d0ce0db901d1bada577cd8f338fc2aec06cb8"
    hash2       = "1a24b75a2a7e52cbe65ddc3ad587a945b24afb617cb2d98581f0b06c49777984"
    hash3       = "4a4141c2adab0ebca262f25d7f6a45b773b074628a9522401e8dfa28d4889ccb"

  strings:
    $s1 = "nction fuck(){return \"Jo\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return" ascii
    $s2 = "return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"ZVi\";})(" ascii
    $s3 = "ction fuck(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){retu" ascii
    $s4 = "Df\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(functio" ascii
    $s5 = "k(){return \"UXf\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IPu\";" ascii
    $s6 = "t\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"USf\";})(),(function" ascii
    $s7 = "nction fuck(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}