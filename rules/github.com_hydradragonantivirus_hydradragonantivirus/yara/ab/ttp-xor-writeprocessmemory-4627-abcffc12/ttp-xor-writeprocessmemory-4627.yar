rule TTP_XOR_WriteProcessMemory_4627 {
  strings:
    $key_4627 = { 11 55 [2] 23 77 [2] 25 42 [2] 0b 42 [2] 34 5e }

  condition:
    any of them
}