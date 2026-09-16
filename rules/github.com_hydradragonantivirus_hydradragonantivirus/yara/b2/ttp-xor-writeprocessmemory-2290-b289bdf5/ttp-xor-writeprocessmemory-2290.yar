rule TTP_XOR_WriteProcessMemory_2290 {
  strings:
    $key_2290 = { 75 e2 [2] 47 c0 [2] 41 f5 [2] 6f f5 [2] 50 e9 }

  condition:
    any of them
}