rule TTP_XOR_WriteProcessMemory_3042 {
  strings:
    $key_3042 = { 67 30 [2] 55 12 [2] 53 27 [2] 7d 27 [2] 42 3b }

  condition:
    any of them
}