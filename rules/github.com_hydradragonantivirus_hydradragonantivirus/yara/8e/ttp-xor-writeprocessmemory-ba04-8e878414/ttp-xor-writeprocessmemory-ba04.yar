rule TTP_XOR_WriteProcessMemory_ba04 {
  strings:
    $key_ba04 = { ed 76 [2] df 54 [2] d9 61 [2] f7 61 [2] c8 7d }

  condition:
    any of them
}