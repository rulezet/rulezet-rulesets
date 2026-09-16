rule TTP_XOR_WriteProcessMemory_ba0b {
  strings:
    $key_ba0b = { ed 79 [2] df 5b [2] d9 6e [2] f7 6e [2] c8 72 }

  condition:
    any of them
}