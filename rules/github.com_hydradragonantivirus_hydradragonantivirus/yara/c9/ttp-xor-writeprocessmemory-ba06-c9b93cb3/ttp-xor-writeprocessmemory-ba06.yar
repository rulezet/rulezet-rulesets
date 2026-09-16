rule TTP_XOR_WriteProcessMemory_ba06 {
  strings:
    $key_ba06 = { ed 74 [2] df 56 [2] d9 63 [2] f7 63 [2] c8 7f }

  condition:
    any of them
}