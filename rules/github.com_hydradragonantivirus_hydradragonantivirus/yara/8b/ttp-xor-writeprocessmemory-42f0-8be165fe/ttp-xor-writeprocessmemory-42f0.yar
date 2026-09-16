rule TTP_XOR_WriteProcessMemory_42f0 {
  strings:
    $key_42f0 = { 15 82 [2] 27 a0 [2] 21 95 [2] 0f 95 [2] 30 89 }

  condition:
    any of them
}