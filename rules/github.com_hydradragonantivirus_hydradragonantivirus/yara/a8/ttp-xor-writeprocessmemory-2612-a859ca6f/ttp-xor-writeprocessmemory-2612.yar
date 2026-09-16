rule TTP_XOR_WriteProcessMemory_2612 {
  strings:
    $key_2612 = { 71 60 [2] 43 42 [2] 45 77 [2] 6b 77 [2] 54 6b }

  condition:
    any of them
}