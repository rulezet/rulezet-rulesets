rule TTP_XOR_WriteProcessMemory_1ce7 {
  strings:
    $key_1ce7 = { 4b 95 [2] 79 b7 [2] 7f 82 [2] 51 82 [2] 6e 9e }

  condition:
    any of them
}