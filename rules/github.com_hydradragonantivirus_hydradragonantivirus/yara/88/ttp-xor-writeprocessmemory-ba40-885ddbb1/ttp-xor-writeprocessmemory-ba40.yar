rule TTP_XOR_WriteProcessMemory_ba40 {
  strings:
    $key_ba40 = { ed 32 [2] df 10 [2] d9 25 [2] f7 25 [2] c8 39 }

  condition:
    any of them
}