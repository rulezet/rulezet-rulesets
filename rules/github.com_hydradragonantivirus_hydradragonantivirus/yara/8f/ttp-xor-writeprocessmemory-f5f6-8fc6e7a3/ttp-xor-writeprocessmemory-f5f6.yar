rule TTP_XOR_WriteProcessMemory_f5f6 {
  strings:
    $key_f5f6 = { a2 84 [2] 90 a6 [2] 96 93 [2] b8 93 [2] 87 8f }

  condition:
    any of them
}