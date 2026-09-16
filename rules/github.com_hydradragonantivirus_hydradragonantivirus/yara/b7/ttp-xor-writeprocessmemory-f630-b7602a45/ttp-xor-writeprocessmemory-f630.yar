rule TTP_XOR_WriteProcessMemory_f630 {
  strings:
    $key_f630 = { a1 42 [2] 93 60 [2] 95 55 [2] bb 55 [2] 84 49 }

  condition:
    any of them
}