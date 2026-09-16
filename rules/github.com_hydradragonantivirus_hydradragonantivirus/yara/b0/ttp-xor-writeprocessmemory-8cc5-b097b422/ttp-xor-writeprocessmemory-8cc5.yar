rule TTP_XOR_WriteProcessMemory_8cc5 {
  strings:
    $key_8cc5 = { db b7 [2] e9 95 [2] ef a0 [2] c1 a0 [2] fe bc }

  condition:
    any of them
}