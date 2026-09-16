rule TTP_XOR_WriteProcessMemory_7527 {
  strings:
    $key_7527 = { 22 55 [2] 10 77 [2] 16 42 [2] 38 42 [2] 07 5e }

  condition:
    any of them
}