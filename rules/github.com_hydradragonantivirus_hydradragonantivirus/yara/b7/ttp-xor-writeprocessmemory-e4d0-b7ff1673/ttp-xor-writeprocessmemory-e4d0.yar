rule TTP_XOR_WriteProcessMemory_e4d0 {
  strings:
    $key_e4d0 = { b3 a2 [2] 81 80 [2] 87 b5 [2] a9 b5 [2] 96 a9 }

  condition:
    any of them
}