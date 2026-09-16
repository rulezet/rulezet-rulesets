rule TTP_XOR_WriteProcessMemory_37e7 {
  strings:
    $key_37e7 = { 60 95 [2] 52 b7 [2] 54 82 [2] 7a 82 [2] 45 9e }

  condition:
    any of them
}