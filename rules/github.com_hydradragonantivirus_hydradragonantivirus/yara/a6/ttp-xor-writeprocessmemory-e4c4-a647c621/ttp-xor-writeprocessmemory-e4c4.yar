rule TTP_XOR_WriteProcessMemory_e4c4 {
  strings:
    $key_e4c4 = { b3 b6 [2] 81 94 [2] 87 a1 [2] a9 a1 [2] 96 bd }

  condition:
    any of them
}