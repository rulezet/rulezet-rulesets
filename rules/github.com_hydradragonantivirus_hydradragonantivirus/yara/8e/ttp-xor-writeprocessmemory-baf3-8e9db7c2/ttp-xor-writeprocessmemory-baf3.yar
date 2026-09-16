rule TTP_XOR_WriteProcessMemory_baf3 {
  strings:
    $key_baf3 = { ed 81 [2] df a3 [2] d9 96 [2] f7 96 [2] c8 8a }

  condition:
    any of them
}