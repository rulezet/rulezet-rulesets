rule TTP_XOR_WriteProcessMemory_ba03 {
  strings:
    $key_ba03 = { ed 71 [2] df 53 [2] d9 66 [2] f7 66 [2] c8 7a }

  condition:
    any of them
}