rule TTP_XOR_WriteProcessMemory_3052 {
  strings:
    $key_3052 = { 67 20 [2] 55 02 [2] 53 37 [2] 7d 37 [2] 42 2b }

  condition:
    any of them
}