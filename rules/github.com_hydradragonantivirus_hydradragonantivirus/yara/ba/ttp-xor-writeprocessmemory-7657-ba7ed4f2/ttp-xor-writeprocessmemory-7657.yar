rule TTP_XOR_WriteProcessMemory_7657 {
  strings:
    $key_7657 = { 21 25 [2] 13 07 [2] 15 32 [2] 3b 32 [2] 04 2e }

  condition:
    any of them
}