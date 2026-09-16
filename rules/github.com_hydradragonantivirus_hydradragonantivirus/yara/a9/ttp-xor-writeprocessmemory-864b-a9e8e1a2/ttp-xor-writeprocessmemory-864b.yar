rule TTP_XOR_WriteProcessMemory_864b {
  strings:
    $key_864b = { d1 39 [2] e3 1b [2] e5 2e [2] cb 2e [2] f4 32 }

  condition:
    any of them
}