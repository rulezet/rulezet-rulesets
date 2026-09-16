rule TTP_XOR_WriteProcessMemory_0f12 {
  strings:
    $key_0f12 = { 58 60 [2] 6a 42 [2] 6c 77 [2] 42 77 [2] 7d 6b }

  condition:
    any of them
}