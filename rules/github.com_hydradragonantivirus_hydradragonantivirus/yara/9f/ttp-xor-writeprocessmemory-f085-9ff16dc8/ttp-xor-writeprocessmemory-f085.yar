rule TTP_XOR_WriteProcessMemory_f085 {
  strings:
    $key_f085 = { a7 f7 [2] 95 d5 [2] 93 e0 [2] bd e0 [2] 82 fc }

  condition:
    any of them
}