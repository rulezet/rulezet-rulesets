rule TTP_XOR_WriteProcessMemory_4980 {
  strings:
    $key_4980 = { 1e f2 [2] 2c d0 [2] 2a e5 [2] 04 e5 [2] 3b f9 }

  condition:
    any of them
}