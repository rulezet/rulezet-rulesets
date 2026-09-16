rule TTP_XOR_WriteProcessMemory_1362 {
  strings:
    $key_1362 = { 44 10 [2] 76 32 [2] 70 07 [2] 5e 07 [2] 61 1b }

  condition:
    any of them
}