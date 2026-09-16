rule TTP_XOR_WriteProcessMemory_d366 {
  strings:
    $key_d366 = { 84 14 [2] b6 36 [2] b0 03 [2] 9e 03 [2] a1 1f }

  condition:
    any of them
}