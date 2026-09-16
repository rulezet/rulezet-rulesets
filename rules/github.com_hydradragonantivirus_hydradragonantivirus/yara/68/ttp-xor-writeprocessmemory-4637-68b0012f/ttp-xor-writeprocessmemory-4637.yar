rule TTP_XOR_WriteProcessMemory_4637 {
  strings:
    $key_4637 = { 11 45 [2] 23 67 [2] 25 52 [2] 0b 52 [2] 34 4e }

  condition:
    any of them
}