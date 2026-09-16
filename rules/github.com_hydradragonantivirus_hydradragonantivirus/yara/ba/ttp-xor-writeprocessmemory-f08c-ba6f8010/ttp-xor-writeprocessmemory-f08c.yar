rule TTP_XOR_WriteProcessMemory_f08c {
  strings:
    $key_f08c = { a7 fe [2] 95 dc [2] 93 e9 [2] bd e9 [2] 82 f5 }

  condition:
    any of them
}