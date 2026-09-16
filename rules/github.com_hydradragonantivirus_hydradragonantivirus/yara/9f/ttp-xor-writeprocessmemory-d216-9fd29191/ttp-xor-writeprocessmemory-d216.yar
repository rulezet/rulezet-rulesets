rule TTP_XOR_WriteProcessMemory_d216 {
  strings:
    $key_d216 = { 85 64 [2] b7 46 [2] b1 73 [2] 9f 73 [2] a0 6f }

  condition:
    any of them
}