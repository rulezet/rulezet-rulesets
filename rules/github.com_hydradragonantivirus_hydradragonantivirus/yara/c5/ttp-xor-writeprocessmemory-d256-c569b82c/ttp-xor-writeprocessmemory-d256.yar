rule TTP_XOR_WriteProcessMemory_d256 {
  strings:
    $key_d256 = { 85 24 [2] b7 06 [2] b1 33 [2] 9f 33 [2] a0 2f }

  condition:
    any of them
}