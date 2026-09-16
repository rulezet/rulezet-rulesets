rule _20160921_207d0a8168d3fb16019724b9f72c41ba_20160921_4f8422c91e79_4660 {
  meta:
    description = "datamaliciousorder - from files 20160921_207d0a8168d3fb16019724b9f72c41ba.js, 20160921_4f8422c91e79e3073e201b0b279b1fbb.js, 20160921_6fabf8ef6df7ba14509fab6de95d721f.js, 20160921_73e0cbee151147d27e01ecc015f640b4.js, 20160921_c979e38640433b8c93e1c145417c85cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90b56af8225bf5087b8c8ea31ab85a80e0951c3a32b8a0a0be7e09ef2efc8172"
    hash2       = "f1cc54af4d213d0cd37c81b29d25c29bf00892e3458ef2e236563c69fd58b94a"
    hash3       = "a6962383b3793edac58fef061128f9047afb39eaa645d3f7977a775ceeb02e56"
    hash4       = "0ad4b632b07e5e4526b874097c116e5183b155ec4b9cf40e3f13ece0ce027344"
    hash5       = "62a468202853ba6a8adb456e8c12b66f8794360c094a85e6d4d2cf43d13a75ce"

  strings:
    $s1 = ",(function fuck(){return \"Jh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Za\";})(),(function fuck(){re" ascii
    $s2 = "eturn \"Jo\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})()," ascii
    $s3 = "on fuck(){return \"Fv\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"M" ascii
    $s4 = "{return \"OQr\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";}" ascii
    $s5 = "GJx\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Xg\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}