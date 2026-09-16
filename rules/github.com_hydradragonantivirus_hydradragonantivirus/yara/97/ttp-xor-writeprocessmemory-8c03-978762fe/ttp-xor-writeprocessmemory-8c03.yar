rule TTP_XOR_WriteProcessMemory_8c03 {
  strings:
    $key_8c03 = { db 71 [2] e9 53 [2] ef 66 [2] c1 66 [2] fe 7a }

  condition:
    any of them
}