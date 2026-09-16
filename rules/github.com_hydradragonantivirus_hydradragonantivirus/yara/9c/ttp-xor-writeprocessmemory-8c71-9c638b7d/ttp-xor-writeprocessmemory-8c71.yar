rule TTP_XOR_WriteProcessMemory_8c71 {
  strings:
    $key_8c71 = { db 03 [2] e9 21 [2] ef 14 [2] c1 14 [2] fe 08 }

  condition:
    any of them
}