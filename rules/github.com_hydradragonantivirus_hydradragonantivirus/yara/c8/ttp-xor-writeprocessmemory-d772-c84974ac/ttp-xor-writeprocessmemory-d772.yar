rule TTP_XOR_WriteProcessMemory_d772 {
  strings:
    $key_d772 = { 80 00 [2] b2 22 [2] b4 17 [2] 9a 17 [2] a5 0b }

  condition:
    any of them
}