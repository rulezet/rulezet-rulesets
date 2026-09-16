rule TTP_XOR_WriteProcessMemory_5fc4 {
  strings:
    $key_5fc4 = { 08 b6 [2] 3a 94 [2] 3c a1 [2] 12 a1 [2] 2d bd }

  condition:
    any of them
}