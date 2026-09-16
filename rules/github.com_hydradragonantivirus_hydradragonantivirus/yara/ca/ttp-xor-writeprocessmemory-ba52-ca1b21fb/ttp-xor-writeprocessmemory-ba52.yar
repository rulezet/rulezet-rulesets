rule TTP_XOR_WriteProcessMemory_ba52 {
  strings:
    $key_ba52 = { ed 20 [2] df 02 [2] d9 37 [2] f7 37 [2] c8 2b }

  condition:
    any of them
}