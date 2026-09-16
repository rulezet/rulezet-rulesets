rule TTP_XOR_WriteProcessMemory_ba70 {
  strings:
    $key_ba70 = { ed 02 [2] df 20 [2] d9 15 [2] f7 15 [2] c8 09 }

  condition:
    any of them
}