rule TTP_XOR_WriteProcessMemory_ba21 {
  strings:
    $key_ba21 = { ed 53 [2] df 71 [2] d9 44 [2] f7 44 [2] c8 58 }

  condition:
    any of them
}