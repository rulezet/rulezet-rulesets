rule TTP_XOR_WriteProcessMemory_d526 {
  strings:
    $key_d526 = { 82 54 [2] b0 76 [2] b6 43 [2] 98 43 [2] a7 5f }

  condition:
    any of them
}