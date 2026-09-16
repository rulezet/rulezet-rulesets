rule TTP_XOR_WriteProcessMemory_3000 {
  strings:
    $key_3000 = { 67 72 [2] 55 50 [2] 53 65 [2] 7d 65 [2] 42 79 }

  condition:
    any of them
}