rule TTP_XOR_WriteProcessMemory_7f12 {
  strings:
    $key_7f12 = { 28 60 [2] 1a 42 [2] 1c 77 [2] 32 77 [2] 0d 6b }

  condition:
    any of them
}