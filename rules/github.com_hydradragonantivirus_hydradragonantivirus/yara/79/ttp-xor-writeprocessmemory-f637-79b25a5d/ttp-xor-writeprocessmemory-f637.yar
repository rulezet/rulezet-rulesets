rule TTP_XOR_WriteProcessMemory_f637 {
  strings:
    $key_f637 = { a1 45 [2] 93 67 [2] 95 52 [2] bb 52 [2] 84 4e }

  condition:
    any of them
}