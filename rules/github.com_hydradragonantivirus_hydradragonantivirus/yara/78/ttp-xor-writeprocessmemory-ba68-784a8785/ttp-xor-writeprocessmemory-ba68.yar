rule TTP_XOR_WriteProcessMemory_ba68 {
  strings:
    $key_ba68 = { ed 1a [2] df 38 [2] d9 0d [2] f7 0d [2] c8 11 }

  condition:
    any of them
}