rule TTP_XOR_WriteProcessMemory_20f3 {
  strings:
    $key_20f3 = { 77 81 [2] 45 a3 [2] 43 96 [2] 6d 96 [2] 52 8a }

  condition:
    any of them
}