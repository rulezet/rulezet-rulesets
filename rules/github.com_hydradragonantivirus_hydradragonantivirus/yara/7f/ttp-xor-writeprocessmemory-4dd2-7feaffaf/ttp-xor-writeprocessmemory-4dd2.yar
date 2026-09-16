rule TTP_XOR_WriteProcessMemory_4dd2 {
  strings:
    $key_4dd2 = { 1a a0 [2] 28 82 [2] 2e b7 [2] 00 b7 [2] 3f ab }

  condition:
    any of them
}