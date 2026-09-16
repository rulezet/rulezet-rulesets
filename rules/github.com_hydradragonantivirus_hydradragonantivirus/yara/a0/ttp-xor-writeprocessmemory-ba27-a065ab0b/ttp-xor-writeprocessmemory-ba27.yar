rule TTP_XOR_WriteProcessMemory_ba27 {
  strings:
    $key_ba27 = { ed 55 [2] df 77 [2] d9 42 [2] f7 42 [2] c8 5e }

  condition:
    any of them
}