rule TTP_XOR_WriteProcessMemory_f659 {
  strings:
    $key_f659 = { a1 2b [2] 93 09 [2] 95 3c [2] bb 3c [2] 84 20 }

  condition:
    any of them
}