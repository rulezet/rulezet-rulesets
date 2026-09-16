rule TTP_XOR_WriteProcessMemory_f708 {
  strings:
    $key_f708 = { a0 7a [2] 92 58 [2] 94 6d [2] ba 6d [2] 85 71 }

  condition:
    any of them
}