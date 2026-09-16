rule TTP_XOR_WriteProcessMemory_5fc1 {
  strings:
    $key_5fc1 = { 08 b3 [2] 3a 91 [2] 3c a4 [2] 12 a4 [2] 2d b8 }

  condition:
    any of them
}