rule TTP_XOR_WriteProcessMemory_8cc1 {
  strings:
    $key_8cc1 = { db b3 [2] e9 91 [2] ef a4 [2] c1 a4 [2] fe b8 }

  condition:
    any of them
}