rule TTP_XOR_WriteProcessMemory_dac0 {
  strings:
    $key_dac0 = { 8d b2 [2] bf 90 [2] b9 a5 [2] 97 a5 [2] a8 b9 }

  condition:
    any of them
}