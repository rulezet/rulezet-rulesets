rule TTP_XOR_WriteProcessMemory_8c01 {
  strings:
    $key_8c01 = { db 73 [2] e9 51 [2] ef 64 [2] c1 64 [2] fe 78 }

  condition:
    any of them
}