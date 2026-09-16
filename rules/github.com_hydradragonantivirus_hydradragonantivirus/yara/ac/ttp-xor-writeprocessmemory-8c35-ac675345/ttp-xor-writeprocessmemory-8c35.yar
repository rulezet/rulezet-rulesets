rule TTP_XOR_WriteProcessMemory_8c35 {
  strings:
    $key_8c35 = { db 47 [2] e9 65 [2] ef 50 [2] c1 50 [2] fe 4c }

  condition:
    any of them
}