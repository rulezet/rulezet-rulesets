rule TTP_XOR_WriteProcessMemory_ba61 {
  strings:
    $key_ba61 = { ed 13 [2] df 31 [2] d9 04 [2] f7 04 [2] c8 18 }

  condition:
    any of them
}