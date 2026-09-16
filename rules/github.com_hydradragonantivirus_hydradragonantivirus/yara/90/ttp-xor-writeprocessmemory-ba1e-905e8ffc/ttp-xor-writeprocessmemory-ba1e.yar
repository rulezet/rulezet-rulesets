rule TTP_XOR_WriteProcessMemory_ba1e {
  strings:
    $key_ba1e = { ed 6c [2] df 4e [2] d9 7b [2] f7 7b [2] c8 67 }

  condition:
    any of them
}