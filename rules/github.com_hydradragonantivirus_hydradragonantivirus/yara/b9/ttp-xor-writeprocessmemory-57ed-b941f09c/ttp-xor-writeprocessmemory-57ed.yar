rule TTP_XOR_WriteProcessMemory_57ed {
  strings:
    $key_57ed = { 00 9f [2] 32 bd [2] 34 88 [2] 1a 88 [2] 25 94 }

  condition:
    any of them
}