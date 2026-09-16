rule TTP_XOR_WriteProcessMemory_ba4d {
  strings:
    $key_ba4d = { ed 3f [2] df 1d [2] d9 28 [2] f7 28 [2] c8 34 }

  condition:
    any of them
}