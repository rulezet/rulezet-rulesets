rule TTP_XOR_WriteProcessMemory_8c64 {
  strings:
    $key_8c64 = { db 16 [2] e9 34 [2] ef 01 [2] c1 01 [2] fe 1d }

  condition:
    any of them
}