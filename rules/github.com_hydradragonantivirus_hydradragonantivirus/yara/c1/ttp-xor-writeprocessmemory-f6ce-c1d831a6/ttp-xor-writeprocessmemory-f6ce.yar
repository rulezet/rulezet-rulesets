rule TTP_XOR_WriteProcessMemory_f6ce {
  strings:
    $key_f6ce = { a1 bc [2] 93 9e [2] 95 ab [2] bb ab [2] 84 b7 }

  condition:
    any of them
}