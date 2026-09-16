rule TTP_XOR_WriteProcessMemory_d146 {
  strings:
    $key_d146 = { 86 34 [2] b4 16 [2] b2 23 [2] 9c 23 [2] a3 3f }

  condition:
    any of them
}