rule TTP_XOR_WriteProcessMemory_ba12 {
  strings:
    $key_ba12 = { ed 60 [2] df 42 [2] d9 77 [2] f7 77 [2] c8 6b }

  condition:
    any of them
}