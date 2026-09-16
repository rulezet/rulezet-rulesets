rule TTP_XOR_WriteProcessMemory_3032 {
  strings:
    $key_3032 = { 67 40 [2] 55 62 [2] 53 57 [2] 7d 57 [2] 42 4b }

  condition:
    any of them
}