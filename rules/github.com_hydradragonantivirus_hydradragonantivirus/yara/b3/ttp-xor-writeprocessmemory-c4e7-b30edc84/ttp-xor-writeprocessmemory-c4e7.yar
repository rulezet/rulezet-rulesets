rule TTP_XOR_WriteProcessMemory_c4e7 {
  strings:
    $key_c4e7 = { 93 95 [2] a1 b7 [2] a7 82 [2] 89 82 [2] b6 9e }

  condition:
    any of them
}