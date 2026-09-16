rule TTP_XOR_WriteProcessMemory_8cf7 {
  strings:
    $key_8cf7 = { db 85 [2] e9 a7 [2] ef 92 [2] c1 92 [2] fe 8e }

  condition:
    any of them
}