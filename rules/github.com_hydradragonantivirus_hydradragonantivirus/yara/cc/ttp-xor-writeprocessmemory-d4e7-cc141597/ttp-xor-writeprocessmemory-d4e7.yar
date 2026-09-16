rule TTP_XOR_WriteProcessMemory_d4e7 {
  strings:
    $key_d4e7 = { 83 95 [2] b1 b7 [2] b7 82 [2] 99 82 [2] a6 9e }

  condition:
    any of them
}