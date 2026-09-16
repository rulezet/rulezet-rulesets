rule TTP_XOR_WriteProcessMemory_d661 {
  strings:
    $key_d661 = { 81 13 [2] b3 31 [2] b5 04 [2] 9b 04 [2] a4 18 }

  condition:
    any of them
}