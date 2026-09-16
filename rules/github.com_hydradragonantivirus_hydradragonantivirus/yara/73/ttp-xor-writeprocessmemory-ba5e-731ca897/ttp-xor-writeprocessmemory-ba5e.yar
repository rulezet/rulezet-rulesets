rule TTP_XOR_WriteProcessMemory_ba5e {
  strings:
    $key_ba5e = { ed 2c [2] df 0e [2] d9 3b [2] f7 3b [2] c8 27 }

  condition:
    any of them
}