rule _20160921_01da6b0c1b5614c5877e0dd7b6be4036_20160921_17642c69cbfb_4125 {
  meta:
    description = "datamaliciousorder - from files 20160921_01da6b0c1b5614c5877e0dd7b6be4036.js, 20160921_17642c69cbfb276056f3695ae22dad4c.js, 20160921_1e07803d7c44ae0b61b5ddf189c80675.js, 20160921_3a2902eaca0b2b91120958418b46c844.js, 20160921_40f63eff81c24c0b6e27053222902225.js, 20160921_460a913db46b41c41035cc210ed5fba0.js, 20160921_4fa304d7c11deb5fb9cd6514d5a983de.js, 20160921_56407ccd21c5f8f4947d4df222e60442.js, 20160921_b23a0d871d76c64a3c71f0b0f52faaa8.js, 20160921_be4748da01602fdf2d9ffd03054028e4.js, 20160921_f5230fc58405f25233bda6815654bd6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5da941f7d098e0926acf7ad9efedc9f91495115fc83f288580eba79e44574693"
    hash2       = "4cdbf9fba4e3fec424cf182fd21fa3c400b0649ca09f140375a47df12248955c"
    hash3       = "1a50e95e48071d391fd7544518c3c0394e9cde9051c76cf311992966b7414cc8"
    hash4       = "063bab1922376d926db97bdcd4342c2e9b0f2ec98d9fad81c2a3f86537c82b07"
    hash5       = "6b71d253d7ac7dfb797132caac458cf74b81e67304218edbb764243d89e51bb1"
    hash6       = "99bd08fbf869b4c9520d81d5b17512d87856474b8cf260494d0c88a47e0d37c9"
    hash7       = "cef5a1e67f57d9f24065ff0145644e0185df6abc29113310c6782b30e0a9236b"
    hash8       = "bec8a0189f43e097fc0815a0bb39f2df50e4c37c7185ad70b3be3b0d17b8dd32"
    hash9       = "02969139df11550b994530c0bcbc6d946b6e49105015e9475f5de3942d78e5a1"
    hash10      = "4847889a558b3e0b60d671ec5082e36330f771c8789f9ae89683bf49e7128616"
    hash11      = "1a813dda7d0088c45bb00563ea79982995ec1337c805380117fe705f80c51c64"

  strings:
    $s1 = "Xf\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"UXf\";})(),(functi" ascii
    $s2 = "(){return \"ZVi\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Mw\";})" ascii
    $s3 = "function fuck(){return \"Na\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){ret" ascii
    $s4 = "})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Fv\";})(),(function fuck" ascii
    $s5 = "tion fuck(){return \"UXf\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}