rule TTP_XOR_WriteProcessMemory_ba4b {
  strings:
    $key_ba4b = { ed 39 [2] df 1b [2] d9 2e [2] f7 2e [2] c8 32 }

  condition:
    any of them
}