rule TTP_XOR_WriteProcessMemory_bac1 {
  strings:
    $key_bac1 = { ed b3 [2] df 91 [2] d9 a4 [2] f7 a4 [2] c8 b8 }

  condition:
    any of them
}