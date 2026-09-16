rule TTP_XOR_WriteProcessMemory_ba1b {
  strings:
    $key_ba1b = { ed 69 [2] df 4b [2] d9 7e [2] f7 7e [2] c8 62 }

  condition:
    any of them
}