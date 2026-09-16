rule TTP_XOR_WriteProcessMemory_6327 {
  strings:
    $key_6327 = { 34 55 [2] 06 77 [2] 00 42 [2] 2e 42 [2] 11 5e }

  condition:
    any of them
}