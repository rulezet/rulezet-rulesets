rule TTP_XOR_WriteProcessMemory_49d0 {
  strings:
    $key_49d0 = { 1e a2 [2] 2c 80 [2] 2a b5 [2] 04 b5 [2] 3b a9 }

  condition:
    any of them
}