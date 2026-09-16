rule TTP_XOR_WriteProcessMemory_bac7 {
  strings:
    $key_bac7 = { ed b5 [2] df 97 [2] d9 a2 [2] f7 a2 [2] c8 be }

  condition:
    any of them
}