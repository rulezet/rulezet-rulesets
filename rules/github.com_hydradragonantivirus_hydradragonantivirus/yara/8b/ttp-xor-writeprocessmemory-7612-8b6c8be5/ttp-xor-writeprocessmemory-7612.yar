rule TTP_XOR_WriteProcessMemory_7612 {
  strings:
    $key_7612 = { 21 60 [2] 13 42 [2] 15 77 [2] 3b 77 [2] 04 6b }

  condition:
    any of them
}