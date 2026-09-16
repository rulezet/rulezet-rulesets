rule TTP_XOR_WriteProcessMemory_ba15 {
  strings:
    $key_ba15 = { ed 67 [2] df 45 [2] d9 70 [2] f7 70 [2] c8 6c }

  condition:
    any of them
}