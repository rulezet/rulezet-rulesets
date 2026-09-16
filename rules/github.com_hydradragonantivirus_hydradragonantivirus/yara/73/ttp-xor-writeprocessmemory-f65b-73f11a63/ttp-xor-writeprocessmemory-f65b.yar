rule TTP_XOR_WriteProcessMemory_f65b {
  strings:
    $key_f65b = { a1 29 [2] 93 0b [2] 95 3e [2] bb 3e [2] 84 22 }

  condition:
    any of them
}