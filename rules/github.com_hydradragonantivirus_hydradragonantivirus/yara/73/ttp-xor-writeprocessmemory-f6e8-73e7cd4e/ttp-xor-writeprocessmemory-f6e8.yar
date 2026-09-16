rule TTP_XOR_WriteProcessMemory_f6e8 {
  strings:
    $key_f6e8 = { a1 9a [2] 93 b8 [2] 95 8d [2] bb 8d [2] 84 91 }

  condition:
    any of them
}