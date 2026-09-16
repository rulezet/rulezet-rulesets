rule TTP_XOR_WriteProcessMemory_8c8d {
  strings:
    $key_8c8d = { db ff [2] e9 dd [2] ef e8 [2] c1 e8 [2] fe f4 }

  condition:
    any of them
}