rule TTP_XOR_WriteProcessMemory_ba6c {
  strings:
    $key_ba6c = { ed 1e [2] df 3c [2] d9 09 [2] f7 09 [2] c8 15 }

  condition:
    any of them
}