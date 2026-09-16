rule TTP_XOR_WriteProcessMemory_07e7 {
  strings:
    $key_07e7 = { 50 95 [2] 62 b7 [2] 64 82 [2] 4a 82 [2] 75 9e }

  condition:
    any of them
}