rule TTP_XOR_WriteProcessMemory_8c0d {
  strings:
    $key_8c0d = { db 7f [2] e9 5d [2] ef 68 [2] c1 68 [2] fe 74 }

  condition:
    any of them
}