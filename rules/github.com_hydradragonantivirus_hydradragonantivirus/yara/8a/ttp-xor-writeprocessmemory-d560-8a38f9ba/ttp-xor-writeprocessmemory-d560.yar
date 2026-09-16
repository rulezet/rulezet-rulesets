rule TTP_XOR_WriteProcessMemory_d560 {
  strings:
    $key_d560 = { 82 12 [2] b0 30 [2] b6 05 [2] 98 05 [2] a7 19 }

  condition:
    any of them
}