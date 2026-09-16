rule TTP_XOR_WriteProcessMemory_8c91 {
  strings:
    $key_8c91 = { db e3 [2] e9 c1 [2] ef f4 [2] c1 f4 [2] fe e8 }

  condition:
    any of them
}