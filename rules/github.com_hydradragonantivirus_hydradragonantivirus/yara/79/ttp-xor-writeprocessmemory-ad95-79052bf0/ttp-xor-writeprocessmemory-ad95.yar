rule TTP_XOR_WriteProcessMemory_ad95 {
  strings:
    $key_ad95 = { fa e7 [2] c8 c5 [2] ce f0 [2] e0 f0 [2] df ec }

  condition:
    any of them
}