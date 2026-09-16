rule TTP_XOR_WriteProcessMemory_6ce7 {
  strings:
    $key_6ce7 = { 3b 95 [2] 09 b7 [2] 0f 82 [2] 21 82 [2] 1e 9e }

  condition:
    any of them
}