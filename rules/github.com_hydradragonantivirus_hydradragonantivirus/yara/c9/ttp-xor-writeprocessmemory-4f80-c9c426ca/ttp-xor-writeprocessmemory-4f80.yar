rule TTP_XOR_WriteProcessMemory_4f80 {
  strings:
    $key_4f80 = { 18 f2 [2] 2a d0 [2] 2c e5 [2] 02 e5 [2] 3d f9 }

  condition:
    any of them
}