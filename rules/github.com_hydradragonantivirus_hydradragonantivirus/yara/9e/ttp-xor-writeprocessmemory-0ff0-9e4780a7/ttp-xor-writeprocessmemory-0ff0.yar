rule TTP_XOR_WriteProcessMemory_0ff0 {
  strings:
    $key_0ff0 = { 58 82 [2] 6a a0 [2] 6c 95 [2] 42 95 [2] 7d 89 }

  condition:
    any of them
}