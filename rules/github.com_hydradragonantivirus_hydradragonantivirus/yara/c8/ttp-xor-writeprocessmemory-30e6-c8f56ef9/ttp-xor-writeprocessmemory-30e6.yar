rule TTP_XOR_WriteProcessMemory_30e6 {
  strings:
    $key_30e6 = { 67 94 [2] 55 b6 [2] 53 83 [2] 7d 83 [2] 42 9f }

  condition:
    any of them
}