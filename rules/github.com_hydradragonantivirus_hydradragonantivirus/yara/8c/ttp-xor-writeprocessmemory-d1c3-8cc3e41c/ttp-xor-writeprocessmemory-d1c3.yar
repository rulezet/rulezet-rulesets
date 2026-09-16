rule TTP_XOR_WriteProcessMemory_d1c3 {
  strings:
    $key_d1c3 = { 86 b1 [2] b4 93 [2] b2 a6 [2] 9c a6 [2] a3 ba }

  condition:
    any of them
}