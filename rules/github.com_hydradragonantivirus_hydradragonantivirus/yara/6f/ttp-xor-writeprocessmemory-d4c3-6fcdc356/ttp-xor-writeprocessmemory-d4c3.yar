rule TTP_XOR_WriteProcessMemory_d4c3 {
  strings:
    $key_d4c3 = { 83 b1 [2] b1 93 [2] b7 a6 [2] 99 a6 [2] a6 ba }

  condition:
    any of them
}