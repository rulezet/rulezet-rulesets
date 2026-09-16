rule TTP_XOR_WriteProcessMemory_2280 {
  strings:
    $key_2280 = { 75 f2 [2] 47 d0 [2] 41 e5 [2] 6f e5 [2] 50 f9 }

  condition:
    any of them
}