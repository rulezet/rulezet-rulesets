rule TTP_XOR_WriteProcessMemory_7427 {
  strings:
    $key_7427 = { 23 55 [2] 11 77 [2] 17 42 [2] 39 42 [2] 06 5e }

  condition:
    any of them
}