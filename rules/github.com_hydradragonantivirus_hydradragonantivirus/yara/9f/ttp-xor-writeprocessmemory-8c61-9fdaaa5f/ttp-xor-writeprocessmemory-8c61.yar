rule TTP_XOR_WriteProcessMemory_8c61 {
  strings:
    $key_8c61 = { db 13 [2] e9 31 [2] ef 04 [2] c1 04 [2] fe 18 }

  condition:
    any of them
}