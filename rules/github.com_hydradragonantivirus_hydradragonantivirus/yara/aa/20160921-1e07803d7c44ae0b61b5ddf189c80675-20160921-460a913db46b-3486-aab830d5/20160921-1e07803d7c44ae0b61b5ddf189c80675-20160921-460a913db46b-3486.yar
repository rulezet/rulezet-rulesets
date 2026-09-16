rule _20160921_1e07803d7c44ae0b61b5ddf189c80675_20160921_460a913db46b_3486 {
  meta:
    description = "datamaliciousorder - from files 20160921_1e07803d7c44ae0b61b5ddf189c80675.js, 20160921_460a913db46b41c41035cc210ed5fba0.js, 20160921_a2f8f3f44ef6a3341feac8fb57e829ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a50e95e48071d391fd7544518c3c0394e9cde9051c76cf311992966b7414cc8"
    hash2       = "99bd08fbf869b4c9520d81d5b17512d87856474b8cf260494d0c88a47e0d37c9"
    hash3       = "619e82812300e58dd7cd06b8fbcf2f7e3f6757812cc075603c82363ab6481758"

  strings:
    $s1 = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return" ascii
    $s2 = "nction fuck(){return \"SUi\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){retur" ascii
    $s3 = "ck(){return \"Xw\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Av\";" ascii
    $s4 = "n fuck(){return \"LLv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return " ascii
    $s5 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"" ascii
    $s6 = "n fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"D" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}