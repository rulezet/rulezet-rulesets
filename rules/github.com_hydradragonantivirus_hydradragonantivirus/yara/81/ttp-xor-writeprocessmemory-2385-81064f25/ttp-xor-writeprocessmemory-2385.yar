rule TTP_XOR_WriteProcessMemory_2385 {
  strings:
    $key_2385 = { 74 f7 [2] 46 d5 [2] 40 e0 [2] 6e e0 [2] 51 fc }

  condition:
    any of them
}