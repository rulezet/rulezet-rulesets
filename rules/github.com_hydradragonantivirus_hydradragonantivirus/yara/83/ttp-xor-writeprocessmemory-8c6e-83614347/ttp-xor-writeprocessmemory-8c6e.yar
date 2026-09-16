rule TTP_XOR_WriteProcessMemory_8c6e {
  strings:
    $key_8c6e = { db 1c [2] e9 3e [2] ef 0b [2] c1 0b [2] fe 17 }

  condition:
    any of them
}