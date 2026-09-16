rule TTP_XOR_WriteProcessMemory_1b57 {
  strings:
    $key_1b57 = { 4c 25 [2] 7e 07 [2] 78 32 [2] 56 32 [2] 69 2e }

  condition:
    any of them
}