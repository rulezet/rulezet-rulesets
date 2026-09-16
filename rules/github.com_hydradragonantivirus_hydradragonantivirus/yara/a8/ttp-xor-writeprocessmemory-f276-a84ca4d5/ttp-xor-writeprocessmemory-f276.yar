rule TTP_XOR_WriteProcessMemory_f276 {
  strings:
    $key_f276 = { a5 04 [2] 97 26 [2] 91 13 [2] bf 13 [2] 80 0f }

  condition:
    any of them
}