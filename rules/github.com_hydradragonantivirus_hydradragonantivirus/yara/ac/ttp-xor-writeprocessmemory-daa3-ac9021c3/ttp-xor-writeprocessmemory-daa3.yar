rule TTP_XOR_WriteProcessMemory_daa3 {
  strings:
    $key_daa3 = { 8d d1 [2] bf f3 [2] b9 c6 [2] 97 c6 [2] a8 da }

  condition:
    any of them
}