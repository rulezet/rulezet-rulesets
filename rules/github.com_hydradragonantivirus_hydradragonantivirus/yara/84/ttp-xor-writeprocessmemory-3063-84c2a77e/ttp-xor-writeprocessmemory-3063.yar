rule TTP_XOR_WriteProcessMemory_3063 {
  strings:
    $key_3063 = { 67 11 [2] 55 33 [2] 53 06 [2] 7d 06 [2] 42 1a }

  condition:
    any of them
}