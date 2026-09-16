rule TTP_XOR_WriteProcessMemory_0dd2 {
  strings:
    $key_0dd2 = { 5a a0 [2] 68 82 [2] 6e b7 [2] 40 b7 [2] 7f ab }

  condition:
    any of them
}