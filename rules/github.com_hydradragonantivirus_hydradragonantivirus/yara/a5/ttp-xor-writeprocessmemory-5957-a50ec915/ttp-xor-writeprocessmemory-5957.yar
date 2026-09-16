rule TTP_XOR_WriteProcessMemory_5957 {
  strings:
    $key_5957 = { 0e 25 [2] 3c 07 [2] 3a 32 [2] 14 32 [2] 2b 2e }

  condition:
    any of them
}