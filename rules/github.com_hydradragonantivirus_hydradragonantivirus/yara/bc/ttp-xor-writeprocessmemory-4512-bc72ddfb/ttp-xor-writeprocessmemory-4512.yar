rule TTP_XOR_WriteProcessMemory_4512 {
  strings:
    $key_4512 = { 12 60 [2] 20 42 [2] 26 77 [2] 08 77 [2] 37 6b }

  condition:
    any of them
}