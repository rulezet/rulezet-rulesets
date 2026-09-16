rule TTP_XOR_WriteProcessMemory_7362 {
  strings:
    $key_7362 = { 24 10 [2] 16 32 [2] 10 07 [2] 3e 07 [2] 01 1b }

  condition:
    any of them
}