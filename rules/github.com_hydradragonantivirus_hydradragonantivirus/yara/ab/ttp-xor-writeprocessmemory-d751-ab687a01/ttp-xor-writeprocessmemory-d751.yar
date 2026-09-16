rule TTP_XOR_WriteProcessMemory_d751 {
  strings:
    $key_d751 = { 80 23 [2] b2 01 [2] b4 34 [2] 9a 34 [2] a5 28 }

  condition:
    any of them
}