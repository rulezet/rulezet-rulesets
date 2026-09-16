rule TTP_XOR_WriteProcessMemory_d226 {
  strings:
    $key_d226 = { 85 54 [2] b7 76 [2] b1 43 [2] 9f 43 [2] a0 5f }

  condition:
    any of them
}