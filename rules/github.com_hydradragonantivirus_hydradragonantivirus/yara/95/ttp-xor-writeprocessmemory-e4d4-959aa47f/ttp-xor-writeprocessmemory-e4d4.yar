rule TTP_XOR_WriteProcessMemory_e4d4 {
  strings:
    $key_e4d4 = { b3 a6 [2] 81 84 [2] 87 b1 [2] a9 b1 [2] 96 ad }

  condition:
    any of them
}