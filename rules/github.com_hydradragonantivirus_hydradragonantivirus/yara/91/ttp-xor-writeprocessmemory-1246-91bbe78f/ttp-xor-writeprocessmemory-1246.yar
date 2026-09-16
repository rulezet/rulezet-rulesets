rule TTP_XOR_WriteProcessMemory_1246 {
  strings:
    $key_1246 = { 45 34 [2] 77 16 [2] 71 23 [2] 5f 23 [2] 60 3f }

  condition:
    any of them
}