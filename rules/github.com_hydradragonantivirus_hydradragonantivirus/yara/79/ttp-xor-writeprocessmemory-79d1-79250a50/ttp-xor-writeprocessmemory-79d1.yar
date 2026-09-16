rule TTP_XOR_WriteProcessMemory_79d1 {
  strings:
    $key_79d1 = { 2e a3 [2] 1c 81 [2] 1a b4 [2] 34 b4 [2] 0b a8 }

  condition:
    any of them
}