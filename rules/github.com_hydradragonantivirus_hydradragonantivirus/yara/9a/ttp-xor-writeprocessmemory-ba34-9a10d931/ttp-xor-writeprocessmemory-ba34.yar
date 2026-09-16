rule TTP_XOR_WriteProcessMemory_ba34 {
  strings:
    $key_ba34 = { ed 46 [2] df 64 [2] d9 51 [2] f7 51 [2] c8 4d }

  condition:
    any of them
}