rule TTP_XOR_WriteProcessMemory_f676 {
  strings:
    $key_f676 = { a1 04 [2] 93 26 [2] 95 13 [2] bb 13 [2] 84 0f }

  condition:
    any of them
}