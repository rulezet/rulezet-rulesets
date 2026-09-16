rule TTP_XOR_WriteProcessMemory_1df6 {
  strings:
    $key_1df6 = { 4a 84 [2] 78 a6 [2] 7e 93 [2] 50 93 [2] 6f 8f }

  condition:
    any of them
}