rule TTP_XOR_WriteProcessMemory_ba2c {
  strings:
    $key_ba2c = { ed 5e [2] df 7c [2] d9 49 [2] f7 49 [2] c8 55 }

  condition:
    any of them
}