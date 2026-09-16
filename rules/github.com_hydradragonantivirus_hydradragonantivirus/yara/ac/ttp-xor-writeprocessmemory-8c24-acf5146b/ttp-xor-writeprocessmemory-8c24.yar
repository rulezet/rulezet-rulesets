rule TTP_XOR_WriteProcessMemory_8c24 {
  strings:
    $key_8c24 = { db 56 [2] e9 74 [2] ef 41 [2] c1 41 [2] fe 5d }

  condition:
    any of them
}