rule TTP_XOR_WriteProcessMemory_8c4c {
  strings:
    $key_8c4c = { db 3e [2] e9 1c [2] ef 29 [2] c1 29 [2] fe 35 }

  condition:
    any of them
}