rule TTP_XOR_WriteProcessMemory_49b0 {
  strings:
    $key_49b0 = { 1e c2 [2] 2c e0 [2] 2a d5 [2] 04 d5 [2] 3b c9 }

  condition:
    any of them
}