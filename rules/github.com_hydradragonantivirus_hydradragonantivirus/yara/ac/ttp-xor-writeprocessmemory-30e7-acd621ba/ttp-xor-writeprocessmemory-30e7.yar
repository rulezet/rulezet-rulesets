rule TTP_XOR_WriteProcessMemory_30e7 {
  strings:
    $key_30e7 = { 67 95 [2] 55 b7 [2] 53 82 [2] 7d 82 [2] 42 9e }

  condition:
    any of them
}