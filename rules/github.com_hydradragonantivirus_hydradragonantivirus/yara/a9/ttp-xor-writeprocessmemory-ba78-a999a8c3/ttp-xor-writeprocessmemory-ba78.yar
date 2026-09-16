rule TTP_XOR_WriteProcessMemory_ba78 {
  strings:
    $key_ba78 = { ed 0a [2] df 28 [2] d9 1d [2] f7 1d [2] c8 01 }

  condition:
    any of them
}