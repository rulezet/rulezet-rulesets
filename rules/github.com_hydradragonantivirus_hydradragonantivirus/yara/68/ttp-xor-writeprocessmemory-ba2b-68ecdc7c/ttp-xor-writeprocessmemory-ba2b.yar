rule TTP_XOR_WriteProcessMemory_ba2b {
  strings:
    $key_ba2b = { ed 59 [2] df 7b [2] d9 4e [2] f7 4e [2] c8 52 }

  condition:
    any of them
}