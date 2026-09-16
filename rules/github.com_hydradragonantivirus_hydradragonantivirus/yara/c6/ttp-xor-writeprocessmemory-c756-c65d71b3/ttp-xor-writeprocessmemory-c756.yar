rule TTP_XOR_WriteProcessMemory_c756 {
  strings:
    $key_c756 = { 90 24 [2] a2 06 [2] a4 33 [2] 8a 33 [2] b5 2f }

  condition:
    any of them
}