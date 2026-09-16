rule TTP_XOR_WriteProcessMemory_c172 {
  strings:
    $key_c172 = { 96 00 [2] a4 22 [2] a2 17 [2] 8c 17 [2] b3 0b }

  condition:
    any of them
}