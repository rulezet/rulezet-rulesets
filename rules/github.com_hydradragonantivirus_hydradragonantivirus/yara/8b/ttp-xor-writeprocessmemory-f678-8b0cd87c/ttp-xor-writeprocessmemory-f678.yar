rule TTP_XOR_WriteProcessMemory_f678 {
  strings:
    $key_f678 = { a1 0a [2] 93 28 [2] 95 1d [2] bb 1d [2] 84 01 }

  condition:
    any of them
}