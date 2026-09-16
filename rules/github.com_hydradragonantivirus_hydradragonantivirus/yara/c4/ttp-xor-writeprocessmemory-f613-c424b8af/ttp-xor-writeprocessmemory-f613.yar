rule TTP_XOR_WriteProcessMemory_f613 {
  strings:
    $key_f613 = { a1 61 [2] 93 43 [2] 95 76 [2] bb 76 [2] 84 6a }

  condition:
    any of them
}