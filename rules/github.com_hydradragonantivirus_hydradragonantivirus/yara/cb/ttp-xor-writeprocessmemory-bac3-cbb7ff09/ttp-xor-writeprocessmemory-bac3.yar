rule TTP_XOR_WriteProcessMemory_bac3 {
  strings:
    $key_bac3 = { ed b1 [2] df 93 [2] d9 a6 [2] f7 a6 [2] c8 ba }

  condition:
    any of them
}