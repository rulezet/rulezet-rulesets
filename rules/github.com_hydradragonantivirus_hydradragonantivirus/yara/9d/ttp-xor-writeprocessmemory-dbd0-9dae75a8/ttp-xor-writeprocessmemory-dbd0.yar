rule TTP_XOR_WriteProcessMemory_dbd0 {
  strings:
    $key_dbd0 = { 8c a2 [2] be 80 [2] b8 b5 [2] 96 b5 [2] a9 a9 }

  condition:
    any of them
}