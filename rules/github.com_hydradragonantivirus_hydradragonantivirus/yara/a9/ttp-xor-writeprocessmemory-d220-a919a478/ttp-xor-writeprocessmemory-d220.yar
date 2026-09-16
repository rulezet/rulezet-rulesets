rule TTP_XOR_WriteProcessMemory_d220 {
  strings:
    $key_d220 = { 85 52 [2] b7 70 [2] b1 45 [2] 9f 45 [2] a0 59 }

  condition:
    any of them
}