rule TTP_XOR_WriteProcessMemory_ad80 {
  strings:
    $key_ad80 = { fa f2 [2] c8 d0 [2] ce e5 [2] e0 e5 [2] df f9 }

  condition:
    any of them
}