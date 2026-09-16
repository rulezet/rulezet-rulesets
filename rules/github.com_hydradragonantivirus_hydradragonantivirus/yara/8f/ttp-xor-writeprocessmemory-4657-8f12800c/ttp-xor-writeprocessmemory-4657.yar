rule TTP_XOR_WriteProcessMemory_4657 {
  strings:
    $key_4657 = { 11 25 [2] 23 07 [2] 25 32 [2] 0b 32 [2] 34 2e }

  condition:
    any of them
}