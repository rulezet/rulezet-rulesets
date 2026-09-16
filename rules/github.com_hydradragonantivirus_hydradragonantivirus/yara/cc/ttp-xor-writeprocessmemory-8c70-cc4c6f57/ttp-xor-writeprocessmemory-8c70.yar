rule TTP_XOR_WriteProcessMemory_8c70 {
  strings:
    $key_8c70 = { db 02 [2] e9 20 [2] ef 15 [2] c1 15 [2] fe 09 }

  condition:
    any of them
}