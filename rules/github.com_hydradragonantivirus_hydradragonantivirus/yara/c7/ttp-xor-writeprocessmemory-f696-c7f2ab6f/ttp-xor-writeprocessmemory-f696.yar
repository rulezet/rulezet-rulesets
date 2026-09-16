rule TTP_XOR_WriteProcessMemory_f696 {
  strings:
    $key_f696 = { a1 e4 [2] 93 c6 [2] 95 f3 [2] bb f3 [2] 84 ef }

  condition:
    any of them
}