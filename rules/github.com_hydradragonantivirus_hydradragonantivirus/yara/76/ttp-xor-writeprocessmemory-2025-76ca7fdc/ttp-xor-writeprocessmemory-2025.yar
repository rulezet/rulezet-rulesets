rule TTP_XOR_WriteProcessMemory_2025 {
  strings:
    $key_2025 = { 77 57 [2] 45 75 [2] 43 40 [2] 6d 40 [2] 52 5c }

  condition:
    any of them
}