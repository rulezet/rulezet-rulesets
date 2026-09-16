rule _20160921_0550bef558fba79f944112d34861e4ec_20160921_0fe6501a0417_4225 {
  meta:
    description = "datamaliciousorder - from files 20160921_0550bef558fba79f944112d34861e4ec.js, 20160921_0fe6501a0417801a0e1868963016e9be.js, 20160921_8d22ed47876b303a1415a88483556238.js, 20160921_e432cba10cde369693d6b125dda112c7.js, 20160922_433c067ed37935e72b4e47664c370c44.js, 20160922_b640840d7ced127a08912e8c9296d442.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cc46901b4b691df366f68f1812df531215964f5150686b06997f1f49b536a1c"
    hash2       = "2926229ccbf6b86ba0ed1aa3ab5b137a43467ffe25d09479a7998c2fdc4b2b30"
    hash3       = "666a3f8cd9a533a20e260aad6bcb18265aad030f6f978c4cc3c9da557262f1ae"
    hash4       = "0f0aa2d80d649fb44a67c6ec77b95eb26709057f543ca215edf15a9bcc4bae4b"
    hash5       = "9070188f3e02706e771ccc37b9b462d58035283f00f156012a41459fa5293e32"
    hash6       = "a67ca3e1e87611dc94e916e6896d144c03fa7f8a6411fdeb74092be2a79bcad4"

  strings:
    $s1 = "){return \"WIj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})(" ascii
    $s2 = "unction f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){ret" ascii
    $s3 = "j\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(functio" ascii
    $s4 = "){return \"Mu\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"RPt\";})" ascii
    $s5 = "0(){return \"RPt\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}