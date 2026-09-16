rule TTP_XOR_WriteProcessMemory_8c5b {
  strings:
    $key_8c5b = { db 29 [2] e9 0b [2] ef 3e [2] c1 3e [2] fe 22 }

  condition:
    any of them
}