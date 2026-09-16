rule TTP_XOR_WriteProcessMemory_0f22 {
  strings:
    $key_0f22 = { 58 50 [2] 6a 72 [2] 6c 47 [2] 42 47 [2] 7d 5b }

  condition:
    any of them
}