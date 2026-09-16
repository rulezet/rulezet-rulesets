rule TTP_XOR_WriteProcessMemory_e4e7 {
  strings:
    $key_e4e7 = { b3 95 [2] 81 b7 [2] 87 82 [2] a9 82 [2] 96 9e }

  condition:
    any of them
}