rule TTP_XOR_WriteProcessMemory_8c77 {
  strings:
    $key_8c77 = { db 05 [2] e9 27 [2] ef 12 [2] c1 12 [2] fe 0e }

  condition:
    any of them
}