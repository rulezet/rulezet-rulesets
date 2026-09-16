rule TTP_XOR_WriteProcessMemory_4fc0 {
  strings:
    $key_4fc0 = { 18 b2 [2] 2a 90 [2] 2c a5 [2] 02 a5 [2] 3d b9 }

  condition:
    any of them
}