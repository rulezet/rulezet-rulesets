rule TTP_XOR_WriteProcessMemory_924b {
  strings:
    $key_924b = { c5 39 [2] f7 1b [2] f1 2e [2] df 2e [2] e0 32 }

  condition:
    any of them
}