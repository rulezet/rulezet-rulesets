rule TTP_XOR_WriteProcessMemory_f63b {
  strings:
    $key_f63b = { a1 49 [2] 93 6b [2] 95 5e [2] bb 5e [2] 84 42 }

  condition:
    any of them
}