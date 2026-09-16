rule TTP_XOR_WriteProcessMemory_c772 {
  strings:
    $key_c772 = { 90 00 [2] a2 22 [2] a4 17 [2] 8a 17 [2] b5 0b }

  condition:
    any of them
}