rule TTP_XOR_WriteProcessMemory_0f40 {
  strings:
    $key_0f40 = { 58 32 [2] 6a 10 [2] 6c 25 [2] 42 25 [2] 7d 39 }

  condition:
    any of them
}