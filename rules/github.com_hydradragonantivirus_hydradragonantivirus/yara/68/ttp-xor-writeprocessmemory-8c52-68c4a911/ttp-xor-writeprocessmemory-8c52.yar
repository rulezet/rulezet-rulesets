rule TTP_XOR_WriteProcessMemory_8c52 {
  strings:
    $key_8c52 = { db 20 [2] e9 02 [2] ef 37 [2] c1 37 [2] fe 2b }

  condition:
    any of them
}