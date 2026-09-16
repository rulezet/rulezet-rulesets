rule TTP_XOR_WriteProcessMemory_3dd2 {
  strings:
    $key_3dd2 = { 6a a0 [2] 58 82 [2] 5e b7 [2] 70 b7 [2] 4f ab }

  condition:
    any of them
}