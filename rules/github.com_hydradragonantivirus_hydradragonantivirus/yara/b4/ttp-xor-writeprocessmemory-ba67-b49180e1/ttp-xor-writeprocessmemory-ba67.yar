rule TTP_XOR_WriteProcessMemory_ba67 {
  strings:
    $key_ba67 = { ed 15 [2] df 37 [2] d9 02 [2] f7 02 [2] c8 1e }

  condition:
    any of them
}