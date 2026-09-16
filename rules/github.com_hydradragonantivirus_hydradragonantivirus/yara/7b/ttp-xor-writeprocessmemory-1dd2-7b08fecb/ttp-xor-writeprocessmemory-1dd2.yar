rule TTP_XOR_WriteProcessMemory_1dd2 {
  strings:
    $key_1dd2 = { 4a a0 [2] 78 82 [2] 7e b7 [2] 50 b7 [2] 6f ab }

  condition:
    any of them
}