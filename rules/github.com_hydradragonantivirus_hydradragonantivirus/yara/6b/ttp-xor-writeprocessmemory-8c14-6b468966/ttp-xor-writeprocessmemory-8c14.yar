rule TTP_XOR_WriteProcessMemory_8c14 {
  strings:
    $key_8c14 = { db 66 [2] e9 44 [2] ef 71 [2] c1 71 [2] fe 6d }

  condition:
    any of them
}