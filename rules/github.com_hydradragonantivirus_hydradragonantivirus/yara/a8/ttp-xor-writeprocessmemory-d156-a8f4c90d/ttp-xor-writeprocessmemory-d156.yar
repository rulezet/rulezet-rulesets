rule TTP_XOR_WriteProcessMemory_d156 {
  strings:
    $key_d156 = { 86 24 [2] b4 06 [2] b2 33 [2] 9c 33 [2] a3 2f }

  condition:
    any of them
}