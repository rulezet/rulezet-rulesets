rule TTP_XOR_WriteProcessMemory_3791 {
  strings:
    $key_3791 = { 60 e3 [2] 52 c1 [2] 54 f4 [2] 7a f4 [2] 45 e8 }

  condition:
    any of them
}