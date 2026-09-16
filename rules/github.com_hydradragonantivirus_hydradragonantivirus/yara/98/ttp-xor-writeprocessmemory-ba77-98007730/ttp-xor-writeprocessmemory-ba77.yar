rule TTP_XOR_WriteProcessMemory_ba77 {
  strings:
    $key_ba77 = { ed 05 [2] df 27 [2] d9 12 [2] f7 12 [2] c8 0e }

  condition:
    any of them
}