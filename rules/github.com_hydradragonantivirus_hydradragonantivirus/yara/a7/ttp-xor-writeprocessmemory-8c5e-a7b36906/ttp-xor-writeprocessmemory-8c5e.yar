rule TTP_XOR_WriteProcessMemory_8c5e {
  strings:
    $key_8c5e = { db 2c [2] e9 0e [2] ef 3b [2] c1 3b [2] fe 27 }

  condition:
    any of them
}