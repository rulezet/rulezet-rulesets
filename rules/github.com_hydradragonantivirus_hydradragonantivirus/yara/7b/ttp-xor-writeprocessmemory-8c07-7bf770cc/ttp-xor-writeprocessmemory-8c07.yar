rule TTP_XOR_WriteProcessMemory_8c07 {
  strings:
    $key_8c07 = { db 75 [2] e9 57 [2] ef 62 [2] c1 62 [2] fe 7e }

  condition:
    any of them
}