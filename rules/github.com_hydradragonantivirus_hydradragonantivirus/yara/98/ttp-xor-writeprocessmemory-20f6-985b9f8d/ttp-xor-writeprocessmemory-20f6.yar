rule TTP_XOR_WriteProcessMemory_20f6 {
  strings:
    $key_20f6 = { 77 84 [2] 45 a6 [2] 43 93 [2] 6d 93 [2] 52 8f }

  condition:
    any of them
}