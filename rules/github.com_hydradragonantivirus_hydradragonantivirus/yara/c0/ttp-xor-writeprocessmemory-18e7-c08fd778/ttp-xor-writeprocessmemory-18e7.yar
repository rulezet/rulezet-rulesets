rule TTP_XOR_WriteProcessMemory_18e7 {
  strings:
    $key_18e7 = { 4f 95 [2] 7d b7 [2] 7b 82 [2] 55 82 [2] 6a 9e }

  condition:
    any of them
}