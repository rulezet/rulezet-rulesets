rule TTP_XOR_WriteProcessMemory_4091 {
  strings:
    $key_4091 = { 17 e3 [2] 25 c1 [2] 23 f4 [2] 0d f4 [2] 32 e8 }

  condition:
    any of them
}