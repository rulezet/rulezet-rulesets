rule TTP_XOR_WriteProcessMemory_0bf7 {
  strings:
    $key_0bf7 = { 5c 85 [2] 6e a7 [2] 68 92 [2] 46 92 [2] 79 8e }

  condition:
    any of them
}