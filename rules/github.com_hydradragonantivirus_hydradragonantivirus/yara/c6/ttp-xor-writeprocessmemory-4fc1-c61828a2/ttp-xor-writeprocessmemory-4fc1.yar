rule TTP_XOR_WriteProcessMemory_4fc1 {
  strings:
    $key_4fc1 = { 18 b3 [2] 2a 91 [2] 2c a4 [2] 02 a4 [2] 3d b8 }

  condition:
    any of them
}