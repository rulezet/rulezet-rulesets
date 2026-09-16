rule TTP_XOR_WriteProcessMemory_8cb9 {
  strings:
    $key_8cb9 = { db cb [2] e9 e9 [2] ef dc [2] c1 dc [2] fe c0 }

  condition:
    any of them
}