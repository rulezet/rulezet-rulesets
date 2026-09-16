rule TTP_XOR_WriteProcessMemory_2c82 {
  strings:
    $key_2c82 = { 7b f0 [2] 49 d2 [2] 4f e7 [2] 61 e7 [2] 5e fb }

  condition:
    any of them
}