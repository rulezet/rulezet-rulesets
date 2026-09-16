rule TTP_XOR_WriteProcessMemory_5de7 {
  strings:
    $key_5de7 = { 0a 95 [2] 38 b7 [2] 3e 82 [2] 10 82 [2] 2f 9e }

  condition:
    any of them
}