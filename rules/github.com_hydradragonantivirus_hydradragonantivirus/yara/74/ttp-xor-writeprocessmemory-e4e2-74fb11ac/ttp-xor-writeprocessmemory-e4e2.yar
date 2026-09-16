rule TTP_XOR_WriteProcessMemory_e4e2 {
  strings:
    $key_e4e2 = { b3 90 [2] 81 b2 [2] 87 87 [2] a9 87 [2] 96 9b }

  condition:
    any of them
}