rule TTP_XOR_WriteProcessMemory_e4a0 {
  strings:
    $key_e4a0 = { b3 d2 [2] 81 f0 [2] 87 c5 [2] a9 c5 [2] 96 d9 }

  condition:
    any of them
}