rule TTP_XOR_WriteProcessMemory_dac3 {
  strings:
    $key_dac3 = { 8d b1 [2] bf 93 [2] b9 a6 [2] 97 a6 [2] a8 ba }

  condition:
    any of them
}