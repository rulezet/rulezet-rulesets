rule TTP_XOR_WriteProcessMemory_8ce4 {
  strings:
    $key_8ce4 = { db 96 [2] e9 b4 [2] ef 81 [2] c1 81 [2] fe 9d }

  condition:
    any of them
}