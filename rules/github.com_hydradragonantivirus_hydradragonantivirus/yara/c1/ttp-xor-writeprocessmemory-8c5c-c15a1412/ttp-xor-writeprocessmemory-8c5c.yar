rule TTP_XOR_WriteProcessMemory_8c5c {
  strings:
    $key_8c5c = { db 2e [2] e9 0c [2] ef 39 [2] c1 39 [2] fe 25 }

  condition:
    any of them
}