rule TTP_XOR_WriteProcessMemory_2490 {
  strings:
    $key_2490 = { 73 e2 [2] 41 c0 [2] 47 f5 [2] 69 f5 [2] 56 e9 }

  condition:
    any of them
}