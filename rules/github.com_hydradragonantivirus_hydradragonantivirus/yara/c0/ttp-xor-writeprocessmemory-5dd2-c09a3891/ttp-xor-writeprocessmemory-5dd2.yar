rule TTP_XOR_WriteProcessMemory_5dd2 {
  strings:
    $key_5dd2 = { 0a a0 [2] 38 82 [2] 3e b7 [2] 10 b7 [2] 2f ab }

  condition:
    any of them
}