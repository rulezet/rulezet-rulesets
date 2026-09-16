rule TTP_XOR_WriteProcessMemory_3573 {
  strings:
    $key_3573 = { 62 01 [2] 50 23 [2] 56 16 [2] 78 16 [2] 47 0a }

  condition:
    any of them
}