rule TTP_XOR_WriteProcessMemory_4b12 {
  strings:
    $key_4b12 = { 1c 60 [2] 2e 42 [2] 28 77 [2] 06 77 [2] 39 6b }

  condition:
    any of them
}