rule TTP_XOR_WriteProcessMemory_d5e7 {
  strings:
    $key_d5e7 = { 82 95 [2] b0 b7 [2] b6 82 [2] 98 82 [2] a7 9e }

  condition:
    any of them
}