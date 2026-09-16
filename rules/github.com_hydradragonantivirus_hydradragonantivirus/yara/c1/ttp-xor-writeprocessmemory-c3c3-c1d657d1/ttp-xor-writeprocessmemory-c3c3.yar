rule TTP_XOR_WriteProcessMemory_c3c3 {
  strings:
    $key_c3c3 = { 94 b1 [2] a6 93 [2] a0 a6 [2] 8e a6 [2] b1 ba }

  condition:
    any of them
}