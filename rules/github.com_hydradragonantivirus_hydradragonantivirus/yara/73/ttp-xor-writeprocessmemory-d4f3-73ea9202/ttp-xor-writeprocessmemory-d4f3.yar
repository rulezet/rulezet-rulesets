rule TTP_XOR_WriteProcessMemory_d4f3 {
  strings:
    $key_d4f3 = { 83 81 [2] b1 a3 [2] b7 96 [2] 99 96 [2] a6 8a }

  condition:
    any of them
}