rule TTP_XOR_WriteProcessMemory_ba7c {
  strings:
    $key_ba7c = { ed 0e [2] df 2c [2] d9 19 [2] f7 19 [2] c8 05 }

  condition:
    any of them
}