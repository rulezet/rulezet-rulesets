rule TTP_XOR_WriteProcessMemory_f608 {
  strings:
    $key_f608 = { a1 7a [2] 93 58 [2] 95 6d [2] bb 6d [2] 84 71 }

  condition:
    any of them
}