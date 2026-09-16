rule TTP_XOR_WriteProcessMemory_20e7 {
  strings:
    $key_20e7 = { 77 95 [2] 45 b7 [2] 43 82 [2] 6d 82 [2] 52 9e }

  condition:
    any of them
}