rule TTP_XOR_WriteProcessMemory_1e12 {
  strings:
    $key_1e12 = { 49 60 [2] 7b 42 [2] 7d 77 [2] 53 77 [2] 6c 6b }

  condition:
    any of them
}