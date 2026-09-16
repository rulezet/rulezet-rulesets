rule _20160921_acc098eb35e159f33783b155bb8929cb_20160921_bd4d87f94769_1617 {
  meta:
    description = "datamaliciousorder - from files 20160921_acc098eb35e159f33783b155bb8929cb.js, 20160921_bd4d87f94769a02253ed6ac2e747557f.js, 20160921_dcd6ef8585af301daafce3419ba14724.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f491f3a68df5684f7bb14dc15b8f6f3dea400dde990f144e6cf0792facdba6e"
    hash2       = "de567d209b0d4353173c2f3ae63037edd6f5695cc5edcdba1dba29b422d963ac"
    hash3       = "599a5b97cea2145a98305cb09031a146a6d64c54509328df8783368c3a3ba008"

  strings:
    $s1  = "turn \"Xg\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Ik\";})(),(f" ascii
    $s2  = "uck(){return \"Za\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq" ascii
    $s3  = "fuck(){return \"Ar\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"MOj" ascii
    $s4  = "nction fuck(){return \"MOj\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){retur" ascii
    $s5  = "turn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Qh\";})(),(" ascii
    $s6  = "})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuc" ascii
    $s7  = "XFd\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Vb\";})(),(functio" ascii
    $s8  = "n \"DAa\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"GWo\";})(),(fu" ascii
    $s9  = " fuck(){return \"MUs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"" ascii
    $s10 = "(){return \"KVh\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Xw\";}" ascii
    $s11 = "ion fuck(){return \"QTc\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return" ascii
    $s12 = ";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Ve\";})(),(function fuc" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}