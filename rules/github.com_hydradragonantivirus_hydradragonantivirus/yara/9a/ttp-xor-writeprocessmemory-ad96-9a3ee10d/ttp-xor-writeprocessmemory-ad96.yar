rule TTP_XOR_WriteProcessMemory_ad96 {
  strings:
    $key_ad96 = { fa e4 [2] c8 c6 [2] ce f3 [2] e0 f3 [2] df ef }

  condition:
    any of them
}