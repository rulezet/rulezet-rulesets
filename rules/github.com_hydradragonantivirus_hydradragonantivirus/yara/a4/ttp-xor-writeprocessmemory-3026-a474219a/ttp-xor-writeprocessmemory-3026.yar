rule TTP_XOR_WriteProcessMemory_3026 {
  strings:
    $key_3026 = { 67 54 [2] 55 76 [2] 53 43 [2] 7d 43 [2] 42 5f }

  condition:
    any of them
}