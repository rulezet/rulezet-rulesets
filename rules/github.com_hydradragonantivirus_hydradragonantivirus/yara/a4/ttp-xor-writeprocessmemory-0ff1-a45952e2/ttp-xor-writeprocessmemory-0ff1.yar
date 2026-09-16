rule TTP_XOR_WriteProcessMemory_0ff1 {
  strings:
    $key_0ff1 = { 58 83 [2] 6a a1 [2] 6c 94 [2] 42 94 [2] 7d 88 }

  condition:
    any of them
}