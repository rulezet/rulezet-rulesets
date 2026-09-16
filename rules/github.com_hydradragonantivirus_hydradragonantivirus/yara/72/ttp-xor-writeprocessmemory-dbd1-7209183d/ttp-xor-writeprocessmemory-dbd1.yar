rule TTP_XOR_WriteProcessMemory_dbd1 {
  strings:
    $key_dbd1 = { 8c a3 [2] be 81 [2] b8 b4 [2] 96 b4 [2] a9 a8 }

  condition:
    any of them
}