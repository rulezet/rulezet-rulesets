rule TTP_XOR_WriteProcessMemory_0fe6 {
  strings:
    $key_0fe6 = { 58 94 [2] 6a b6 [2] 6c 83 [2] 42 83 [2] 7d 9f }

  condition:
    any of them
}