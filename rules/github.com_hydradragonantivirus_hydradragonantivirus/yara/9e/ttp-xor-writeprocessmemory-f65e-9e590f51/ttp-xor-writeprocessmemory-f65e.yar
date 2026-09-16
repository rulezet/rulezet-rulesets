rule TTP_XOR_WriteProcessMemory_f65e {
  strings:
    $key_f65e = { a1 2c [2] 93 0e [2] 95 3b [2] bb 3b [2] 84 27 }

  condition:
    any of them
}