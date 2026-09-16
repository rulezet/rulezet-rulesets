rule TTP_XOR_WriteProcessMemory_d606 {
  strings:
    $key_d606 = { 81 74 [2] b3 56 [2] b5 63 [2] 9b 63 [2] a4 7f }

  condition:
    any of them
}