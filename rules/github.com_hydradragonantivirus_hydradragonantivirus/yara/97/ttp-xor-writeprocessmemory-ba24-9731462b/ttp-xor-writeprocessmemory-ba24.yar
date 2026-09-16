rule TTP_XOR_WriteProcessMemory_ba24 {
  strings:
    $key_ba24 = { ed 56 [2] df 74 [2] d9 41 [2] f7 41 [2] c8 5d }

  condition:
    any of them
}