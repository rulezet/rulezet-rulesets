rule TTP_XOR_WriteProcessMemory_f622 {
  strings:
    $key_f622 = { a1 50 [2] 93 72 [2] 95 47 [2] bb 47 [2] 84 5b }

  condition:
    any of them
}