rule TTP_XOR_WriteProcessMemory_8c7c {
  strings:
    $key_8c7c = { db 0e [2] e9 2c [2] ef 19 [2] c1 19 [2] fe 05 }

  condition:
    any of them
}