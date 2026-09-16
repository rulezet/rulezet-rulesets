rule TTP_XOR_WriteProcessMemory_5b57 {
  strings:
    $key_5b57 = { 0c 25 [2] 3e 07 [2] 38 32 [2] 16 32 [2] 29 2e }

  condition:
    any of them
}