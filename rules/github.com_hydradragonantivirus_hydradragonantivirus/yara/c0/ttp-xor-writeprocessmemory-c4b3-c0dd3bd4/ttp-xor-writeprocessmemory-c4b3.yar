rule TTP_XOR_WriteProcessMemory_c4b3 {
  strings:
    $key_c4b3 = { 93 c1 [2] a1 e3 [2] a7 d6 [2] 89 d6 [2] b6 ca }

  condition:
    any of them
}