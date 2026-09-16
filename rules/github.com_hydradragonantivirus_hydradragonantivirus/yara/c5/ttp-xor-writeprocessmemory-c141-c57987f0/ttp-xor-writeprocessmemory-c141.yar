rule TTP_XOR_WriteProcessMemory_c141 {
  strings:
    $key_c141 = { 96 33 [2] a4 11 [2] a2 24 [2] 8c 24 [2] b3 38 }

  condition:
    any of them
}