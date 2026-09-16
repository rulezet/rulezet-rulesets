rule TTP_XOR_WriteProcessMemory_7dd2 {
  strings:
    $key_7dd2 = { 2a a0 [2] 18 82 [2] 1e b7 [2] 30 b7 [2] 0f ab }

  condition:
    any of them
}