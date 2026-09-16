rule TTP_XOR_WriteProcessMemory_3045 {
  strings:
    $key_3045 = { 67 37 [2] 55 15 [2] 53 20 [2] 7d 20 [2] 42 3c }

  condition:
    any of them
}