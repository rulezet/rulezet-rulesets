rule TTP_XOR_WriteProcessMemory_c5f3 {
  strings:
    $key_c5f3 = { 92 81 [2] a0 a3 [2] a6 96 [2] 88 96 [2] b7 8a }

  condition:
    any of them
}