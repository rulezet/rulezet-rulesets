rule TTP_XOR_WriteProcessMemory_2740 {
  strings:
    $key_2740 = { 70 32 [2] 42 10 [2] 44 25 [2] 6a 25 [2] 55 39 }

  condition:
    any of them
}