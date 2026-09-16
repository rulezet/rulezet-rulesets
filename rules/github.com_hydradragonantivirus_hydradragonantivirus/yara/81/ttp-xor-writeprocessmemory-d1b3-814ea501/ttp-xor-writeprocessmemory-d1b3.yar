rule TTP_XOR_WriteProcessMemory_d1b3 {
  strings:
    $key_d1b3 = { 86 c1 [2] b4 e3 [2] b2 d6 [2] 9c d6 [2] a3 ca }

  condition:
    any of them
}