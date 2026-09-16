rule TTP_XOR_WriteProcessMemory_d266 {
  strings:
    $key_d266 = { 85 14 [2] b7 36 [2] b1 03 [2] 9f 03 [2] a0 1f }

  condition:
    any of them
}