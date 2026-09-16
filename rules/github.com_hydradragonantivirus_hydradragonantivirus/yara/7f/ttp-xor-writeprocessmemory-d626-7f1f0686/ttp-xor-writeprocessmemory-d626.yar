rule TTP_XOR_WriteProcessMemory_d626 {
  strings:
    $key_d626 = { 81 54 [2] b3 76 [2] b5 43 [2] 9b 43 [2] a4 5f }

  condition:
    any of them
}