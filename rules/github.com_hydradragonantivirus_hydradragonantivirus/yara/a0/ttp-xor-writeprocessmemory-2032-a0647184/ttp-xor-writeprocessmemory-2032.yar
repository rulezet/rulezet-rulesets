rule TTP_XOR_WriteProcessMemory_2032 {
  strings:
    $key_2032 = { 77 40 [2] 45 62 [2] 43 57 [2] 6d 57 [2] 52 4b }

  condition:
    any of them
}