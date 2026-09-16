rule TTP_XOR_WriteProcessMemory_8c13 {
  strings:
    $key_8c13 = { db 61 [2] e9 43 [2] ef 76 [2] c1 76 [2] fe 6a }

  condition:
    any of them
}