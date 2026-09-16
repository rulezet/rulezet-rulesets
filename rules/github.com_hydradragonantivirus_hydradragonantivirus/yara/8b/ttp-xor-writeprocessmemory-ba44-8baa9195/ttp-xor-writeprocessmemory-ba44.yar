rule TTP_XOR_WriteProcessMemory_ba44 {
  strings:
    $key_ba44 = { ed 36 [2] df 14 [2] d9 21 [2] f7 21 [2] c8 3d }

  condition:
    any of them
}