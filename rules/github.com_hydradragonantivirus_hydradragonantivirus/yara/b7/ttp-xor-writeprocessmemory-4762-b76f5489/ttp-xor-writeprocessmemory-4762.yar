rule TTP_XOR_WriteProcessMemory_4762 {
  strings:
    $key_4762 = { 10 10 [2] 22 32 [2] 24 07 [2] 0a 07 [2] 35 1b }

  condition:
    any of them
}