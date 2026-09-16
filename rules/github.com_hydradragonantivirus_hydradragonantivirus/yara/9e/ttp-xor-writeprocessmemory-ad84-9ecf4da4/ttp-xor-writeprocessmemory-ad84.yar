rule TTP_XOR_WriteProcessMemory_ad84 {
  strings:
    $key_ad84 = { fa f6 [2] c8 d4 [2] ce e1 [2] e0 e1 [2] df fd }

  condition:
    any of them
}