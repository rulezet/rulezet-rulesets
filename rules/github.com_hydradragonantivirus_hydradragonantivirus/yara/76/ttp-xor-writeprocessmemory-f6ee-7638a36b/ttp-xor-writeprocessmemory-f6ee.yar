rule TTP_XOR_WriteProcessMemory_f6ee {
  strings:
    $key_f6ee = { a1 9c [2] 93 be [2] 95 8b [2] bb 8b [2] 84 97 }

  condition:
    any of them
}