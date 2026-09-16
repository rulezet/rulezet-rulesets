rule TTP_XOR_WriteProcessMemory_baf6 {
  strings:
    $key_baf6 = { ed 84 [2] df a6 [2] d9 93 [2] f7 93 [2] c8 8f }

  condition:
    any of them
}