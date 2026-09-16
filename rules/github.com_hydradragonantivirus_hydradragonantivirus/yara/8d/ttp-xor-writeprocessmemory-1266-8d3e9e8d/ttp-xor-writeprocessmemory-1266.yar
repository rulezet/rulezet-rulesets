rule TTP_XOR_WriteProcessMemory_1266 {
  strings:
    $key_1266 = { 45 14 [2] 77 36 [2] 71 03 [2] 5f 03 [2] 60 1f }

  condition:
    any of them
}