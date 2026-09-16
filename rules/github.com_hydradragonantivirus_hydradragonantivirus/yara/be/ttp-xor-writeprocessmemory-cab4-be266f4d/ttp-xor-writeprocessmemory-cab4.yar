rule TTP_XOR_WriteProcessMemory_cab4 {
  strings:
    $key_cab4 = { 9d c6 [2] af e4 [2] a9 d1 [2] 87 d1 [2] b8 cd }

  condition:
    any of them
}