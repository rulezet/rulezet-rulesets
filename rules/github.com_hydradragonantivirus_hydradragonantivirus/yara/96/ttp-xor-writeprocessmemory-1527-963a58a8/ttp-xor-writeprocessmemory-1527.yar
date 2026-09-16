rule TTP_XOR_WriteProcessMemory_1527 {
  strings:
    $key_1527 = { 42 55 [2] 70 77 [2] 76 42 [2] 58 42 [2] 67 5e }

  condition:
    any of them
}