rule TTP_XOR_WriteProcessMemory_f60e {
  strings:
    $key_f60e = { a1 7c [2] 93 5e [2] 95 6b [2] bb 6b [2] 84 77 }

  condition:
    any of them
}