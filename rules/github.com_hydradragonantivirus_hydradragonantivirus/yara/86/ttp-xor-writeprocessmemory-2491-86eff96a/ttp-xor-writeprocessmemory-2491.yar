rule TTP_XOR_WriteProcessMemory_2491 {
  strings:
    $key_2491 = { 73 e3 [2] 41 c1 [2] 47 f4 [2] 69 f4 [2] 56 e8 }

  condition:
    any of them
}