rule TTP_XOR_WriteProcessMemory_5fc0 {
  strings:
    $key_5fc0 = { 08 b2 [2] 3a 90 [2] 3c a5 [2] 12 a5 [2] 2d b9 }

  condition:
    any of them
}