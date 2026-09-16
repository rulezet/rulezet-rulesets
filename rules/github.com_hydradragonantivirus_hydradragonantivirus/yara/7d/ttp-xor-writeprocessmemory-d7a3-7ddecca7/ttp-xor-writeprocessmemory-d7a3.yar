rule TTP_XOR_WriteProcessMemory_d7a3 {
  strings:
    $key_d7a3 = { 80 d1 [2] b2 f3 [2] b4 c6 [2] 9a c6 [2] a5 da }

  condition:
    any of them
}