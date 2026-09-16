rule TTP_XOR_WriteProcessMemory_ba20 {
  strings:
    $key_ba20 = { ed 52 [2] df 70 [2] d9 45 [2] f7 45 [2] c8 59 }

  condition:
    any of them
}