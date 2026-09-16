rule TTP_XOR_WriteProcessMemory_4707 {
  strings:
    $key_4707 = { 10 75 [2] 22 57 [2] 24 62 [2] 0a 62 [2] 35 7e }

  condition:
    any of them
}