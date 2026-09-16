rule TTP_XOR_WriteProcessMemory_d5b3 {
  strings:
    $key_d5b3 = { 82 c1 [2] b0 e3 [2] b6 d6 [2] 98 d6 [2] a7 ca }

  condition:
    any of them
}