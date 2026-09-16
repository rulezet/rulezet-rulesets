rule TTP_XOR_WriteProcessMemory_17e7 {
  strings:
    $key_17e7 = { 40 95 [2] 72 b7 [2] 74 82 [2] 5a 82 [2] 65 9e }

  condition:
    any of them
}