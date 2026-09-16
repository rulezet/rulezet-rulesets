rule TTP_XOR_WriteProcessMemory_869b {
  strings:
    $key_869b = { d1 e9 [2] e3 cb [2] e5 fe [2] cb fe [2] f4 e2 }

  condition:
    any of them
}