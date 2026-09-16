rule TTP_XOR_WriteProcessMemory_6d94 {
  strings:
    $key_6d94 = { 3a e6 [2] 08 c4 [2] 0e f1 [2] 20 f1 [2] 1f ed }

  condition:
    any of them
}