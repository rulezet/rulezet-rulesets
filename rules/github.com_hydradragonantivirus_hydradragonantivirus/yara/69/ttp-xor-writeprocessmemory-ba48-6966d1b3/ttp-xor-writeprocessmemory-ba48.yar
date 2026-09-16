rule TTP_XOR_WriteProcessMemory_ba48 {
  strings:
    $key_ba48 = { ed 3a [2] df 18 [2] d9 2d [2] f7 2d [2] c8 31 }

  condition:
    any of them
}