rule TTP_XOR_WriteProcessMemory_3b57 {
  strings:
    $key_3b57 = { 6c 25 [2] 5e 07 [2] 58 32 [2] 76 32 [2] 49 2e }

  condition:
    any of them
}