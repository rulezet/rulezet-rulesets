rule TTP_XOR_WriteProcessMemory_2291 {
  strings:
    $key_2291 = { 75 e3 [2] 47 c1 [2] 41 f4 [2] 6f f4 [2] 50 e8 }

  condition:
    any of them
}