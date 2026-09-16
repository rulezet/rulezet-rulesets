rule TTP_XOR_WriteProcessMemory_8c15 {
  strings:
    $key_8c15 = { db 67 [2] e9 45 [2] ef 70 [2] c1 70 [2] fe 6c }

  condition:
    any of them
}