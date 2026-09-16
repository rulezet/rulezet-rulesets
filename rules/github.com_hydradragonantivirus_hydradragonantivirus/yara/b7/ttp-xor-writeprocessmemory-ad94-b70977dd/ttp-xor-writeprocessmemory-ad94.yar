rule TTP_XOR_WriteProcessMemory_ad94 {
  strings:
    $key_ad94 = { fa e6 [2] c8 c4 [2] ce f1 [2] e0 f1 [2] df ed }

  condition:
    any of them
}