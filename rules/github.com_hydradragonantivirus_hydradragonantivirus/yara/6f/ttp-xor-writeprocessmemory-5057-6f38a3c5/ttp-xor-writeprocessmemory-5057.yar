rule TTP_XOR_WriteProcessMemory_5057 {
  strings:
    $key_5057 = { 07 25 [2] 35 07 [2] 33 32 [2] 1d 32 [2] 22 2e }

  condition:
    any of them
}