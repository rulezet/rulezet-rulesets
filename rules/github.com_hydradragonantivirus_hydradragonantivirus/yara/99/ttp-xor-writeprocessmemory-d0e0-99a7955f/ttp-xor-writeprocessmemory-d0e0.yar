rule TTP_XOR_WriteProcessMemory_d0e0 {
  strings:
    $key_d0e0 = { 87 92 [2] b5 b0 [2] b3 85 [2] 9d 85 [2] a2 99 }

  condition:
    any of them
}