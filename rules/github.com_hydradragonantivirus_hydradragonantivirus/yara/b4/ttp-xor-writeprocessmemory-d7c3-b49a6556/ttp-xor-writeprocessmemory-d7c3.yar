rule TTP_XOR_WriteProcessMemory_d7c3 {
  strings:
    $key_d7c3 = { 80 b1 [2] b2 93 [2] b4 a6 [2] 9a a6 [2] a5 ba }

  condition:
    any of them
}