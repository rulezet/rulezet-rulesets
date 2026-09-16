rule TTP_XOR_WriteProcessMemory_7707 {
  strings:
    $key_7707 = { 20 75 [2] 12 57 [2] 14 62 [2] 3a 62 [2] 05 7e }

  condition:
    any of them
}