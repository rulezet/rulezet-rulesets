rule TTP_XOR_WriteProcessMemory_f635 {
  strings:
    $key_f635 = { a1 47 [2] 93 65 [2] 95 50 [2] bb 50 [2] 84 4c }

  condition:
    any of them
}