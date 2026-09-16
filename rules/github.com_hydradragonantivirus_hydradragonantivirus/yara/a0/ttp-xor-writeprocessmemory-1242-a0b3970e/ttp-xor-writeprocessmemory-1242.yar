rule TTP_XOR_WriteProcessMemory_1242 {
  strings:
    $key_1242 = { 45 30 [2] 77 12 [2] 71 27 [2] 5f 27 [2] 60 3b }

  condition:
    any of them
}