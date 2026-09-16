rule TTP_XOR_WriteProcessMemory_3bf7 {
  strings:
    $key_3bf7 = { 6c 85 [2] 5e a7 [2] 58 92 [2] 76 92 [2] 49 8e }

  condition:
    any of them
}