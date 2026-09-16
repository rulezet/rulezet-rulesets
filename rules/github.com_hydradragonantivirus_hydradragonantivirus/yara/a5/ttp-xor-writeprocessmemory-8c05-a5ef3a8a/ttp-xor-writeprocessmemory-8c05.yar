rule TTP_XOR_WriteProcessMemory_8c05 {
  strings:
    $key_8c05 = { db 77 [2] e9 55 [2] ef 60 [2] c1 60 [2] fe 7c }

  condition:
    any of them
}