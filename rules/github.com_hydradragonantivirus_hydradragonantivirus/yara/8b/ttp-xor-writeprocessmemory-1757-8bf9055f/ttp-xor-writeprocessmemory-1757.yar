rule TTP_XOR_WriteProcessMemory_1757 {
  strings:
    $key_1757 = { 40 25 [2] 72 07 [2] 74 32 [2] 5a 32 [2] 65 2e }

  condition:
    any of them
}