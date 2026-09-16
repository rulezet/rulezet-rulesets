rule TTP_XOR_WriteProcessMemory_ba7e {
  strings:
    $key_ba7e = { ed 0c [2] df 2e [2] d9 1b [2] f7 1b [2] c8 07 }

  condition:
    any of them
}