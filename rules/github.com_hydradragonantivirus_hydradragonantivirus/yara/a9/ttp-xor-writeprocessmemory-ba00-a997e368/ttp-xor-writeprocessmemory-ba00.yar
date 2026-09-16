rule TTP_XOR_WriteProcessMemory_ba00 {
  strings:
    $key_ba00 = { ed 72 [2] df 50 [2] d9 65 [2] f7 65 [2] c8 79 }

  condition:
    any of them
}