rule TTP_XOR_WriteProcessMemory_d6b3 {
  strings:
    $key_d6b3 = { 81 c1 [2] b3 e3 [2] b5 d6 [2] 9b d6 [2] a4 ca }

  condition:
    any of them
}