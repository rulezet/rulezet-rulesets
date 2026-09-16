rule TTP_XOR_WriteProcessMemory_f6e7 {
  strings:
    $key_f6e7 = { a1 95 [2] 93 b7 [2] 95 82 [2] bb 82 [2] 84 9e }

  condition:
    any of them
}