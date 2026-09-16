rule TTP_XOR_WriteProcessMemory_f656 {
  strings:
    $key_f656 = { a1 24 [2] 93 06 [2] 95 33 [2] bb 33 [2] 84 2f }

  condition:
    any of them
}