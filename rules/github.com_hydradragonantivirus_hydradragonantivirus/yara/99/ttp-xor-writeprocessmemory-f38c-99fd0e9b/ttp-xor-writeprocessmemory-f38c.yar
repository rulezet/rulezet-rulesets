rule TTP_XOR_WriteProcessMemory_f38c {
  strings:
    $key_f38c = { a4 fe [2] 96 dc [2] 90 e9 [2] be e9 [2] 81 f5 }

  condition:
    any of them
}