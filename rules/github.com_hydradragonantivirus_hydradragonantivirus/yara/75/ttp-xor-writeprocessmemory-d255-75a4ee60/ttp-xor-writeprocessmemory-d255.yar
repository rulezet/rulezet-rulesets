rule TTP_XOR_WriteProcessMemory_d255 {
  strings:
    $key_d255 = { 85 27 [2] b7 05 [2] b1 30 [2] 9f 30 [2] a0 2c }

  condition:
    any of them
}