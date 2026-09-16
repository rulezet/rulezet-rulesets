rule TTP_XOR_WriteProcessMemory_75c0 {
  strings:
    $key_75c0 = { 22 b2 [2] 10 90 [2] 16 a5 [2] 38 a5 [2] 07 b9 }

  condition:
    any of them
}