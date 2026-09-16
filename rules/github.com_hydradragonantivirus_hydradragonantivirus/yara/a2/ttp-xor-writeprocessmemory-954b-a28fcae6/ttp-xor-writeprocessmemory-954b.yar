rule TTP_XOR_WriteProcessMemory_954b {
  strings:
    $key_954b = { c2 39 [2] f0 1b [2] f6 2e [2] d8 2e [2] e7 32 }

  condition:
    any of them
}