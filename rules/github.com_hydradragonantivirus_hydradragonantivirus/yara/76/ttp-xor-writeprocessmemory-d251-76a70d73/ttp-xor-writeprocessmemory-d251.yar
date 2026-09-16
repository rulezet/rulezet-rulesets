rule TTP_XOR_WriteProcessMemory_d251 {
  strings:
    $key_d251 = { 85 23 [2] b7 01 [2] b1 34 [2] 9f 34 [2] a0 28 }

  condition:
    any of them
}