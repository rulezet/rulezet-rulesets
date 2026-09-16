rule TTP_XOR_WriteProcessMemory_8c0c {
  strings:
    $key_8c0c = { db 7e [2] e9 5c [2] ef 69 [2] c1 69 [2] fe 75 }

  condition:
    any of them
}