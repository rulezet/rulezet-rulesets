rule TTP_XOR_WriteProcessMemory_4d94 {
  strings:
    $key_4d94 = { 1a e6 [2] 28 c4 [2] 2e f1 [2] 00 f1 [2] 3f ed }

  condition:
    any of them
}