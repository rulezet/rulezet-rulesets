rule TTP_XOR_WriteProcessMemory_17c0 {
  strings:
    $key_17c0 = { 40 b2 [2] 72 90 [2] 74 a5 [2] 5a a5 [2] 65 b9 }

  condition:
    any of them
}