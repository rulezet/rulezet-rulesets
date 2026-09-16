rule TTP_XOR_WriteProcessMemory_e4e0 {
  strings:
    $key_e4e0 = { b3 92 [2] 81 b0 [2] 87 85 [2] a9 85 [2] 96 99 }

  condition:
    any of them
}