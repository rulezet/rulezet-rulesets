rule TTP_XOR_WriteProcessMemory_c1c3 {
  strings:
    $key_c1c3 = { 96 b1 [2] a4 93 [2] a2 a6 [2] 8c a6 [2] b3 ba }

  condition:
    any of them
}