rule TTP_XOR_WriteProcessMemory_20f5 {
  strings:
    $key_20f5 = { 77 87 [2] 45 a5 [2] 43 90 [2] 6d 90 [2] 52 8c }

  condition:
    any of them
}