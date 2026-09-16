rule TTP_XOR_WriteProcessMemory_dac4 {
  strings:
    $key_dac4 = { 8d b6 [2] bf 94 [2] b9 a1 [2] 97 a1 [2] a8 bd }

  condition:
    any of them
}