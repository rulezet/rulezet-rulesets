rule TTP_XOR_WriteProcessMemory_40d4 {
  strings:
    $key_40d4 = { 17 a6 [2] 25 84 [2] 23 b1 [2] 0d b1 [2] 32 ad }

  condition:
    any of them
}