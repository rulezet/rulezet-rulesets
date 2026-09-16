rule TTP_XOR_WriteProcessMemory_e490 {
  strings:
    $key_e490 = { b3 e2 [2] 81 c0 [2] 87 f5 [2] a9 f5 [2] 96 e9 }

  condition:
    any of them
}