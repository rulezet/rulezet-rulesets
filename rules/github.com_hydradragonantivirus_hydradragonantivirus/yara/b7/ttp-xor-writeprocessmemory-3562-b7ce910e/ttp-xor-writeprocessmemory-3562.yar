rule TTP_XOR_WriteProcessMemory_3562 {
  strings:
    $key_3562 = { 62 10 [2] 50 32 [2] 56 07 [2] 78 07 [2] 47 1b }

  condition:
    any of them
}