rule TTP_XOR_WriteProcessMemory_e4e1 {
  strings:
    $key_e4e1 = { b3 93 [2] 81 b1 [2] 87 84 [2] a9 84 [2] 96 98 }

  condition:
    any of them
}