rule TTP_XOR_WriteProcessMemory_49f1 {
  strings:
    $key_49f1 = { 1e 83 [2] 2c a1 [2] 2a 94 [2] 04 94 [2] 3b 88 }

  condition:
    any of them
}