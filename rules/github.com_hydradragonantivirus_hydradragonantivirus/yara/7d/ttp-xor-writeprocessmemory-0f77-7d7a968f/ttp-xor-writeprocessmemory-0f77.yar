rule TTP_XOR_WriteProcessMemory_0f77 {
  strings:
    $key_0f77 = { 58 05 [2] 6a 27 [2] 6c 12 [2] 42 12 [2] 7d 0e }

  condition:
    any of them
}