rule TTP_XOR_WriteProcessMemory_ddd0 {
  strings:
    $key_ddd0 = { 8a a2 [2] b8 80 [2] be b5 [2] 90 b5 [2] af a9 }

  condition:
    any of them
}