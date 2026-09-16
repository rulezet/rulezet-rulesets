rule TTP_XOR_WriteProcessMemory_3302 {
  strings:
    $key_3302 = { 64 70 [2] 56 52 [2] 50 67 [2] 7e 67 [2] 41 7b }

  condition:
    any of them
}