rule TTP_XOR_WriteProcessMemory_2791 {
  strings:
    $key_2791 = { 70 e3 [2] 42 c1 [2] 44 f4 [2] 6a f4 [2] 55 e8 }

  condition:
    any of them
}