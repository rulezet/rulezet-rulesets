rule TTP_XOR_WriteProcessMemory_5fc5 {
  strings:
    $key_5fc5 = { 08 b7 [2] 3a 95 [2] 3c a0 [2] 12 a0 [2] 2d bc }

  condition:
    any of them
}