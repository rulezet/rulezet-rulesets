rule TTP_XOR_WriteProcessMemory_0ff7 {
  strings:
    $key_0ff7 = { 58 85 [2] 6a a7 [2] 6c 92 [2] 42 92 [2] 7d 8e }

  condition:
    any of them
}