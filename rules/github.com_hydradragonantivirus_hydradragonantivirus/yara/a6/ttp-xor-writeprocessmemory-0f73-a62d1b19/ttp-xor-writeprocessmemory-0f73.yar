rule TTP_XOR_WriteProcessMemory_0f73 {
  strings:
    $key_0f73 = { 58 01 [2] 6a 23 [2] 6c 16 [2] 42 16 [2] 7d 0a }

  condition:
    any of them
}