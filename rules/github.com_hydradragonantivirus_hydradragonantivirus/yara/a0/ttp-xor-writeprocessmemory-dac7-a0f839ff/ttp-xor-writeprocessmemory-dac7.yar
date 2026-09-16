rule TTP_XOR_WriteProcessMemory_dac7 {
  strings:
    $key_dac7 = { 8d b5 [2] bf 97 [2] b9 a2 [2] 97 a2 [2] a8 be }

  condition:
    any of them
}