rule TTP_XOR_WriteProcessMemory_f636 {
  strings:
    $key_f636 = { a1 44 [2] 93 66 [2] 95 53 [2] bb 53 [2] 84 4f }

  condition:
    any of them
}