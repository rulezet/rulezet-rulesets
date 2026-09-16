rule TTP_XOR_WriteProcessMemory_f3f6 {
  strings:
    $key_f3f6 = { a4 84 [2] 96 a6 [2] 90 93 [2] be 93 [2] 81 8f }

  condition:
    any of them
}