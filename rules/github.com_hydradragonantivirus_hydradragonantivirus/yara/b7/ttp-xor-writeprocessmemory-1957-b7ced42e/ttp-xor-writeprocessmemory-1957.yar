rule TTP_XOR_WriteProcessMemory_1957 {
  strings:
    $key_1957 = { 4e 25 [2] 7c 07 [2] 7a 32 [2] 54 32 [2] 6b 2e }

  condition:
    any of them
}