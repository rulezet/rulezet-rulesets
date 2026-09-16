rule TTP_XOR_WriteProcessMemory_4fb1 {
  strings:
    $key_4fb1 = { 18 c3 [2] 2a e1 [2] 2c d4 [2] 02 d4 [2] 3d c8 }

  condition:
    any of them
}