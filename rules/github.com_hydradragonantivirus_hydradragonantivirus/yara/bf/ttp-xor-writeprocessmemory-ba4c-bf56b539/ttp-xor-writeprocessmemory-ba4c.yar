rule TTP_XOR_WriteProcessMemory_ba4c {
  strings:
    $key_ba4c = { ed 3e [2] df 1c [2] d9 29 [2] f7 29 [2] c8 35 }

  condition:
    any of them
}