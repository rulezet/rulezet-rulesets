rule TTP_XOR_WriteProcessMemory_8c0b {
  strings:
    $key_8c0b = { db 79 [2] e9 5b [2] ef 6e [2] c1 6e [2] fe 72 }

  condition:
    any of them
}