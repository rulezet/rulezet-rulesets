rule TTP_XOR_WriteProcessMemory_c126 {
  strings:
    $key_c126 = { 96 54 [2] a4 76 [2] a2 43 [2] 8c 43 [2] b3 5f }

  condition:
    any of them
}