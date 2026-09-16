rule TTP_XOR_WriteProcessMemory_8ce5 {
  strings:
    $key_8ce5 = { db 97 [2] e9 b5 [2] ef 80 [2] c1 80 [2] fe 9c }

  condition:
    any of them
}