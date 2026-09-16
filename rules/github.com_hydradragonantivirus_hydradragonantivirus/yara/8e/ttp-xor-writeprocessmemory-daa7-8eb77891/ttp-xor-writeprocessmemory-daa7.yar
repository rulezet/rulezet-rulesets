rule TTP_XOR_WriteProcessMemory_daa7 {
  strings:
    $key_daa7 = { 8d d5 [2] bf f7 [2] b9 c2 [2] 97 c2 [2] a8 de }

  condition:
    any of them
}