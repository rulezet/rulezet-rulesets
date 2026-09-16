rule TTP_XOR_WriteProcessMemory_f6e4 {
  strings:
    $key_f6e4 = { a1 96 [2] 93 b4 [2] 95 81 [2] bb 81 [2] 84 9d }

  condition:
    any of them
}