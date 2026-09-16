rule TTP_XOR_WriteProcessMemory_ead1 {
  strings:
    $key_ead1 = { bd a3 [2] 8f 81 [2] 89 b4 [2] a7 b4 [2] 98 a8 }

  condition:
    any of them
}