rule TTP_XOR_WriteProcessMemory_7f77 {
  strings:
    $key_7f77 = { 28 05 [2] 1a 27 [2] 1c 12 [2] 32 12 [2] 0d 0e }

  condition:
    any of them
}