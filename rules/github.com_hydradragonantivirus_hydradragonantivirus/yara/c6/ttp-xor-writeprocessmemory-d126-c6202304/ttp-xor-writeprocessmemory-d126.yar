rule TTP_XOR_WriteProcessMemory_d126 {
  strings:
    $key_d126 = { 86 54 [2] b4 76 [2] b2 43 [2] 9c 43 [2] a3 5f }

  condition:
    any of them
}