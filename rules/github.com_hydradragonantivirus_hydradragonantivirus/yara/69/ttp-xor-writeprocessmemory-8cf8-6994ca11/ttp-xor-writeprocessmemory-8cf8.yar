rule TTP_XOR_WriteProcessMemory_8cf8 {
  strings:
    $key_8cf8 = { db 8a [2] e9 a8 [2] ef 9d [2] c1 9d [2] fe 81 }

  condition:
    any of them
}