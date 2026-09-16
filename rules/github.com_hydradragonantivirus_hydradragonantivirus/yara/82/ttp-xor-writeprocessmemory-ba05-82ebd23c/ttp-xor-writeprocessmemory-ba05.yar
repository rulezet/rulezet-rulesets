rule TTP_XOR_WriteProcessMemory_ba05 {
  strings:
    $key_ba05 = { ed 77 [2] df 55 [2] d9 60 [2] f7 60 [2] c8 7c }

  condition:
    any of them
}