rule TTP_XOR_WriteProcessMemory_c526 {
  strings:
    $key_c526 = { 92 54 [2] a0 76 [2] a6 43 [2] 88 43 [2] b7 5f }

  condition:
    any of them
}