rule TTP_XOR_WriteProcessMemory_ba32 {
  strings:
    $key_ba32 = { ed 40 [2] df 62 [2] d9 57 [2] f7 57 [2] c8 4b }

  condition:
    any of them
}