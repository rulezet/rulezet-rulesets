rule TTP_XOR_WriteProcessMemory_4340 {
  strings:
    $key_4340 = { 14 32 [2] 26 10 [2] 20 25 [2] 0e 25 [2] 31 39 }

  condition:
    any of them
}