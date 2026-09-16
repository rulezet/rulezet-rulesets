rule TTP_XOR_WriteProcessMemory_0f42 {
  strings:
    $key_0f42 = { 58 30 [2] 6a 12 [2] 6c 27 [2] 42 27 [2] 7d 3b }

  condition:
    any of them
}