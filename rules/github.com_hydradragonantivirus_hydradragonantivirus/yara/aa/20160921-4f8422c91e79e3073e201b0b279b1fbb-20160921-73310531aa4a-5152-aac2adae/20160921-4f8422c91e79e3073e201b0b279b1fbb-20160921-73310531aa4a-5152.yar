rule _20160921_4f8422c91e79e3073e201b0b279b1fbb_20160921_73310531aa4a_5152 {
  meta:
    description = "datamaliciousorder - from files 20160921_4f8422c91e79e3073e201b0b279b1fbb.js, 20160921_73310531aa4a1df7337a6ef42003ce5e.js, 20160921_73e0cbee151147d27e01ecc015f640b4.js, 20160921_97811319fb50bbd834b521ddcbb35712.js, 20160921_c979e38640433b8c93e1c145417c85cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1cc54af4d213d0cd37c81b29d25c29bf00892e3458ef2e236563c69fd58b94a"
    hash2       = "c1f6942ac4bb494bebef47181bbb9c9fe04d3d155e4bc18b2ff21e74c6592f78"
    hash3       = "0ad4b632b07e5e4526b874097c116e5183b155ec4b9cf40e3f13ece0ce027344"
    hash4       = "4105b34a1f3797b1fc5f9b5d7f49d995c2796d5876f07b87b344f6c7e8c0625e"
    hash5       = "62a468202853ba6a8adb456e8c12b66f8794360c094a85e6d4d2cf43d13a75ce"

  strings:
    $s1 = "})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Fv\";})(),(function fuck(" ascii
    $s2 = "\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Pc\";})(),(function f" ascii
    $s3 = "rn \"Ug\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Xg\";})(),(fun" ascii
    $s4 = ",(function fuck(){return \"QTc\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck()" ascii
    $s5 = "n fuck(){return \"Fv\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"F" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}