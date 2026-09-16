rule TTP_XOR_WriteProcessMemory_ea12 {
  strings:
    $key_ea12 = { bd 60 [2] 8f 42 [2] 89 77 [2] a7 77 [2] 98 6b }

  condition:
    any of them
}