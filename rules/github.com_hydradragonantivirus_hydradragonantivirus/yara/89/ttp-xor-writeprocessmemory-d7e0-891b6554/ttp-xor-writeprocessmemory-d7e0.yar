rule TTP_XOR_WriteProcessMemory_d7e0 {
  strings:
    $key_d7e0 = { 80 92 [2] b2 b0 [2] b4 85 [2] 9a 85 [2] a5 99 }

  condition:
    any of them
}