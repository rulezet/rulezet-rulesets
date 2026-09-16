rule TTP_XOR_WriteProcessMemory_c160 {
  strings:
    $key_c160 = { 96 12 [2] a4 30 [2] a2 05 [2] 8c 05 [2] b3 19 }

  condition:
    any of them
}