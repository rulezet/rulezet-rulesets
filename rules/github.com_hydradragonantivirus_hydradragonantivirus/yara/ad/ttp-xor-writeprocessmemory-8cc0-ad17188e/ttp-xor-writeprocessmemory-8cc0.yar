rule TTP_XOR_WriteProcessMemory_8cc0 {
  strings:
    $key_8cc0 = { db b2 [2] e9 90 [2] ef a5 [2] c1 a5 [2] fe b9 }

  condition:
    any of them
}