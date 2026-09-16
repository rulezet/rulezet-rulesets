rule TTP_XOR_WriteProcessMemory_7733 {
  strings:
    $key_7733 = { 20 41 [2] 12 63 [2] 14 56 [2] 3a 56 [2] 05 4a }

  condition:
    any of them
}