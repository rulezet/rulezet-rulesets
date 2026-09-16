rule TTP_XOR_WriteProcessMemory_ba07 {
  strings:
    $key_ba07 = { ed 75 [2] df 57 [2] d9 62 [2] f7 62 [2] c8 7e }

  condition:
    any of them
}