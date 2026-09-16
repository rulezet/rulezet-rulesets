rule TTP_XOR_WriteProcessMemory_f67c {
  strings:
    $key_f67c = { a1 0e [2] 93 2c [2] 95 19 [2] bb 19 [2] 84 05 }

  condition:
    any of them
}