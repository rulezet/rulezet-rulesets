rule TTP_XOR_WriteProcessMemory_8c97 {
  strings:
    $key_8c97 = { db e5 [2] e9 c7 [2] ef f2 [2] c1 f2 [2] fe ee }

  condition:
    any of them
}