rule _20160921_4f8422c91e79e3073e201b0b279b1fbb_20160921_73e0cbee1511_3760 {
  meta:
    description = "datamaliciousorder - from files 20160921_4f8422c91e79e3073e201b0b279b1fbb.js, 20160921_73e0cbee151147d27e01ecc015f640b4.js, 20160921_7ab823078d2353d978403d071ad27626.js, 20160921_82861e992460412d02ca3f987da7d467.js, 20160921_c979e38640433b8c93e1c145417c85cb.js, 20160921_e0f7b2a32a0967097baa59c67369ba3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1cc54af4d213d0cd37c81b29d25c29bf00892e3458ef2e236563c69fd58b94a"
    hash2       = "0ad4b632b07e5e4526b874097c116e5183b155ec4b9cf40e3f13ece0ce027344"
    hash3       = "32692e808eb087cfb43babd004792978a1918b8bad58bd7576ad1e83a17c97f8"
    hash4       = "2ed6678fea06b2b66ef873575f3af904bb62f54913a37c77387208fd53da33ba"
    hash5       = "62a468202853ba6a8adb456e8c12b66f8794360c094a85e6d4d2cf43d13a75ce"
    hash6       = "d527617da74d553b6d56b37f7b101c14280b85e5e40e1f565fe396f8b97b29a2"

  strings:
    $s1 = "k(){return \"DRx\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Vb\";" ascii
    $s2 = "return \"Ot\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"MOj\";})(" ascii
    $s3 = "nction fuck(){return \"DRx\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){retu" ascii
    $s4 = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return" ascii
    $s5 = "{return \"ZVi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})" ascii
    $s6 = " \"OQr\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Np\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}