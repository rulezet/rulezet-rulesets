rule _20160921_eba3e9dc8ad614a7e5c422a93cd7b424_20160921_fff847efa0ea_5728 {
  meta:
    description = "datamaliciousorder - from files 20160921_eba3e9dc8ad614a7e5c422a93cd7b424.js, 20160921_fff847efa0eaa326a0aad4d2fc81d41e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0f6c6f4fe3daf7aae3b8d7276adbcc6577a8bf844eeae945023523b63b6cc9a"
    hash2       = "93f868a10878cb41f305e28c8802778903c99b84a1bc0647a0c2c78fd6310577"

  strings:
    $s1 = "){return \"WIj\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"GGn\";})" ascii
    $s2 = "})(),(function f000(){return \"Sv\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"MDb\";})(),(function f00" ascii
    $s3 = "function f000(){return \"Qz\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"XTn\";})(),(function f000(){ret" ascii
    $s4 = "f000(){return \"MDb\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"UE" ascii
    $s5 = "turn \"Um\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"TKl\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}