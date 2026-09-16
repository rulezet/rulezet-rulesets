rule TTP_XOR_WriteProcessMemory_ba56 {
  strings:
    $key_ba56 = { ed 24 [2] df 06 [2] d9 33 [2] f7 33 [2] c8 2f }

  condition:
    any of them
}