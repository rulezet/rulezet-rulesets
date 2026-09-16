rule TTP_XOR_WriteProcessMemory_35e7 {
  strings:
    $key_35e7 = { 62 95 [2] 50 b7 [2] 56 82 [2] 78 82 [2] 47 9e }

  condition:
    any of them
}