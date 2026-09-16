rule TTP_XOR_WriteProcessMemory_dac1 {
  strings:
    $key_dac1 = { 8d b3 [2] bf 91 [2] b9 a4 [2] 97 a4 [2] a8 b8 }

  condition:
    any of them
}