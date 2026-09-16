rule TTP_XOR_WriteProcessMemory_4037 {
  strings:
    $key_4037 = { 17 45 [2] 25 67 [2] 23 52 [2] 0d 52 [2] 32 4e }

  condition:
    any of them
}