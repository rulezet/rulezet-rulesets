rule TTP_XOR_WriteProcessMemory_c226 {
  strings:
    $key_c226 = { 95 54 [2] a7 76 [2] a1 43 [2] 8f 43 [2] b0 5f }

  condition:
    any of them
}