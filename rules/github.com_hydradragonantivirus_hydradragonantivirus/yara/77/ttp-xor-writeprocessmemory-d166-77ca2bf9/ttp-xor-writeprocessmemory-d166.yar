rule TTP_XOR_WriteProcessMemory_d166 {
  strings:
    $key_d166 = { 86 14 [2] b4 36 [2] b2 03 [2] 9c 03 [2] a3 1f }

  condition:
    any of them
}