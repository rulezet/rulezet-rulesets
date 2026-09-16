rule _20160921_4809ff2679793c2b9af03e18ec3702ef_20160921_4f8422c91e79_5084 {
  meta:
    description = "datamaliciousorder - from files 20160921_4809ff2679793c2b9af03e18ec3702ef.js, 20160921_4f8422c91e79e3073e201b0b279b1fbb.js, 20160921_73e0cbee151147d27e01ecc015f640b4.js, 20160921_c979e38640433b8c93e1c145417c85cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c2d464143196a0237396460d274213cf5b3de772f4205aee0525b67ca1bfd6c"
    hash2       = "f1cc54af4d213d0cd37c81b29d25c29bf00892e3458ef2e236563c69fd58b94a"
    hash3       = "0ad4b632b07e5e4526b874097c116e5183b155ec4b9cf40e3f13ece0ce027344"
    hash4       = "62a468202853ba6a8adb456e8c12b66f8794360c094a85e6d4d2cf43d13a75ce"

  strings:
    $s1 = "function fuck(){return \"Ve\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){ret" ascii
    $s2 = "),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Ot\";})(),(function fuck()" ascii
    $s3 = "c\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(functio" ascii
    $s4 = "\"Zy\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(funct" ascii
    $s5 = "uck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"EHo" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}