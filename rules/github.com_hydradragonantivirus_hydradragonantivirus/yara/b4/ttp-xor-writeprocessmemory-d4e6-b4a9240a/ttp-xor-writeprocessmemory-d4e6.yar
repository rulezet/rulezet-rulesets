rule TTP_XOR_WriteProcessMemory_d4e6 {
  strings:
    $key_d4e6 = { 83 94 [2] b1 b6 [2] b7 83 [2] 99 83 [2] a6 9f }

  condition:
    any of them
}