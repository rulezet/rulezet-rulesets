rule TTP_XOR_WriteProcessMemory_4002 {
  strings:
    $key_4002 = { 17 70 [2] 25 52 [2] 23 67 [2] 0d 67 [2] 32 7b }

  condition:
    any of them
}