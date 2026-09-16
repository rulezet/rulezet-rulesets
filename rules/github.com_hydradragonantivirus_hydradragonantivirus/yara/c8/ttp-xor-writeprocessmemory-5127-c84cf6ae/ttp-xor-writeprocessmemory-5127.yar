rule TTP_XOR_WriteProcessMemory_5127 {
  strings:
    $key_5127 = { 06 55 [2] 34 77 [2] 32 42 [2] 1c 42 [2] 23 5e }

  condition:
    any of them
}