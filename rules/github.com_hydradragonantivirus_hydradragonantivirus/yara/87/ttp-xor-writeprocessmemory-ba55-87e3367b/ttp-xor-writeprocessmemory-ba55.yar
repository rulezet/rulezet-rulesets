rule TTP_XOR_WriteProcessMemory_ba55 {
  strings:
    $key_ba55 = { ed 27 [2] df 05 [2] d9 30 [2] f7 30 [2] c8 2c }

  condition:
    any of them
}