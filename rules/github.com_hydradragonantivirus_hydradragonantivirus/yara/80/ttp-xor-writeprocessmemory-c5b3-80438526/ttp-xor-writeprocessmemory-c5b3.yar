rule TTP_XOR_WriteProcessMemory_c5b3 {
  strings:
    $key_c5b3 = { 92 c1 [2] a0 e3 [2] a6 d6 [2] 88 d6 [2] b7 ca }

  condition:
    any of them
}