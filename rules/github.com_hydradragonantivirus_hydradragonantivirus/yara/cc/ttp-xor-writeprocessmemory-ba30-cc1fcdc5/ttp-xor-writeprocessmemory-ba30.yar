rule TTP_XOR_WriteProcessMemory_ba30 {
  strings:
    $key_ba30 = { ed 42 [2] df 60 [2] d9 55 [2] f7 55 [2] c8 49 }

  condition:
    any of them
}