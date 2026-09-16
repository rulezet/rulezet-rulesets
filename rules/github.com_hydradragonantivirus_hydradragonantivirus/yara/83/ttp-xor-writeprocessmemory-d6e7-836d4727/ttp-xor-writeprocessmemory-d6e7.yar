rule TTP_XOR_WriteProcessMemory_d6e7 {
  strings:
    $key_d6e7 = { 81 95 [2] b3 b7 [2] b5 82 [2] 9b 82 [2] a4 9e }

  condition:
    any of them
}