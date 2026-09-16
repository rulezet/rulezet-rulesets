rule TTP_XOR_WriteProcessMemory_79b0 {
  strings:
    $key_79b0 = { 2e c2 [2] 1c e0 [2] 1a d5 [2] 34 d5 [2] 0b c9 }

  condition:
    any of them
}