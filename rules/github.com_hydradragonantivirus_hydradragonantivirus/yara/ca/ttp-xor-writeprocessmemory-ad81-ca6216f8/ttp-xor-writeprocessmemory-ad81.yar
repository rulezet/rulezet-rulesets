rule TTP_XOR_WriteProcessMemory_ad81 {
  strings:
    $key_ad81 = { fa f3 [2] c8 d1 [2] ce e4 [2] e0 e4 [2] df f8 }

  condition:
    any of them
}