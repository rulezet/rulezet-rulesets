rule TTP_XOR_WriteProcessMemory_dac5 {
  strings:
    $key_dac5 = { 8d b7 [2] bf 95 [2] b9 a0 [2] 97 a0 [2] a8 bc }

  condition:
    any of them
}