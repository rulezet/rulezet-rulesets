rule TTP_XOR_WriteProcessMemory_07e1 {
  strings:
    $key_07e1 = { 50 93 [2] 62 b1 [2] 64 84 [2] 4a 84 [2] 75 98 }

  condition:
    any of them
}