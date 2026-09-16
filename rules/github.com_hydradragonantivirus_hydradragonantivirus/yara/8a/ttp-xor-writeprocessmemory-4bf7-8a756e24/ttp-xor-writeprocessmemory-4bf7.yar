rule TTP_XOR_WriteProcessMemory_4bf7 {
  strings:
    $key_4bf7 = { 1c 85 [2] 2e a7 [2] 28 92 [2] 06 92 [2] 39 8e }

  condition:
    any of them
}