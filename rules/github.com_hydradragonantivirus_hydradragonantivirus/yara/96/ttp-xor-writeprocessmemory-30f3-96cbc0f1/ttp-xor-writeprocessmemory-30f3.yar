rule TTP_XOR_WriteProcessMemory_30f3 {
  strings:
    $key_30f3 = { 67 81 [2] 55 a3 [2] 53 96 [2] 7d 96 [2] 42 8a }

  condition:
    any of them
}