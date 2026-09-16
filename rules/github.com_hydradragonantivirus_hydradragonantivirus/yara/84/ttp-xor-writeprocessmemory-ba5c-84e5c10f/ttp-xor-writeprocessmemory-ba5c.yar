rule TTP_XOR_WriteProcessMemory_ba5c {
  strings:
    $key_ba5c = { ed 2e [2] df 0c [2] d9 39 [2] f7 39 [2] c8 25 }

  condition:
    any of them
}