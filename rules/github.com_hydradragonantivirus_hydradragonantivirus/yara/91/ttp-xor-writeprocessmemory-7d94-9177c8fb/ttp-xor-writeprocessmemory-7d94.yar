rule TTP_XOR_WriteProcessMemory_7d94 {
  strings:
    $key_7d94 = { 2a e6 [2] 18 c4 [2] 1e f1 [2] 30 f1 [2] 0f ed }

  condition:
    any of them
}