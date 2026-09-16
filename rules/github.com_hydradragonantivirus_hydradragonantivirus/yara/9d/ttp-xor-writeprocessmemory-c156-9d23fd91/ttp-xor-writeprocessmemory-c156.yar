rule TTP_XOR_WriteProcessMemory_c156 {
  strings:
    $key_c156 = { 96 24 [2] a4 06 [2] a2 33 [2] 8c 33 [2] b3 2f }

  condition:
    any of them
}