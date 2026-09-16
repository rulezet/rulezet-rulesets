rule TTP_XOR_WriteProcessMemory_c566 {
  strings:
    $key_c566 = { 92 14 [2] a0 36 [2] a6 03 [2] 88 03 [2] b7 1f }

  condition:
    any of them
}