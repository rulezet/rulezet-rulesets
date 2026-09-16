rule TTP_XOR_WriteProcessMemory_c461 {
  strings:
    $key_c461 = { 93 13 [2] a1 31 [2] a7 04 [2] 89 04 [2] b6 18 }

  condition:
    any of them
}