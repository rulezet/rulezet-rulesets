rule TTP_XOR_WriteProcessMemory_4b57 {
  strings:
    $key_4b57 = { 1c 25 [2] 2e 07 [2] 28 32 [2] 06 32 [2] 39 2e }

  condition:
    any of them
}