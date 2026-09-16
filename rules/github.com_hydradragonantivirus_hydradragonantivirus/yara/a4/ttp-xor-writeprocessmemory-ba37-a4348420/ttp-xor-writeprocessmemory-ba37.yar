rule TTP_XOR_WriteProcessMemory_ba37 {
  strings:
    $key_ba37 = { ed 45 [2] df 67 [2] d9 52 [2] f7 52 [2] c8 4e }

  condition:
    any of them
}