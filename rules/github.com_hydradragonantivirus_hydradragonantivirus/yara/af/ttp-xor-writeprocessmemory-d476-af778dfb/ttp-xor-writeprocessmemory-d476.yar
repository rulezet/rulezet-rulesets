rule TTP_XOR_WriteProcessMemory_d476 {
  strings:
    $key_d476 = { 83 04 [2] b1 26 [2] b7 13 [2] 99 13 [2] a6 0f }

  condition:
    any of them
}