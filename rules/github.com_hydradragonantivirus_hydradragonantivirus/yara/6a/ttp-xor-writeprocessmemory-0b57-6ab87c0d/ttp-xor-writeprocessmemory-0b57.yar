rule TTP_XOR_WriteProcessMemory_0b57 {
  strings:
    $key_0b57 = { 5c 25 [2] 6e 07 [2] 68 32 [2] 46 32 [2] 79 2e }

  condition:
    any of them
}