rule TTP_XOR_WriteProcessMemory_daa0 {
  strings:
    $key_daa0 = { 8d d2 [2] bf f0 [2] b9 c5 [2] 97 c5 [2] a8 d9 }

  condition:
    any of them
}