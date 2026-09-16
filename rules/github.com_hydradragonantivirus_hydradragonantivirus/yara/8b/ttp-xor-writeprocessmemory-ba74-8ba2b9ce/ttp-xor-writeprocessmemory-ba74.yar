rule TTP_XOR_WriteProcessMemory_ba74 {
  strings:
    $key_ba74 = { ed 06 [2] df 24 [2] d9 11 [2] f7 11 [2] c8 0d }

  condition:
    any of them
}