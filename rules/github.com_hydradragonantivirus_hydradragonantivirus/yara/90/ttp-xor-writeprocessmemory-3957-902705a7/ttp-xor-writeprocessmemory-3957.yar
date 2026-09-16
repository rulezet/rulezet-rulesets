rule TTP_XOR_WriteProcessMemory_3957 {
  strings:
    $key_3957 = { 6e 25 [2] 5c 07 [2] 5a 32 [2] 74 32 [2] 4b 2e }

  condition:
    any of them
}