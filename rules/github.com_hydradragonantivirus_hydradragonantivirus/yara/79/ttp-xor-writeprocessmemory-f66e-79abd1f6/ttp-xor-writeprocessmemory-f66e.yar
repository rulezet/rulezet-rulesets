rule TTP_XOR_WriteProcessMemory_f66e {
  strings:
    $key_f66e = { a1 1c [2] 93 3e [2] 95 0b [2] bb 0b [2] 84 17 }

  condition:
    any of them
}