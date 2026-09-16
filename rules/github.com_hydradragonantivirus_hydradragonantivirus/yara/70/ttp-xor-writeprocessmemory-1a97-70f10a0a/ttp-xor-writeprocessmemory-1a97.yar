rule TTP_XOR_WriteProcessMemory_1a97 {
  strings:
    $key_1a97 = { 4d e5 [2] 7f c7 [2] 79 f2 [2] 57 f2 [2] 68 ee }

  condition:
    any of them
}