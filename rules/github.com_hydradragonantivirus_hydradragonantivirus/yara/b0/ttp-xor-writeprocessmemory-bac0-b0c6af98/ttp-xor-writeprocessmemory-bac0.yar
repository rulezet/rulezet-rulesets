rule TTP_XOR_WriteProcessMemory_bac0 {
  strings:
    $key_bac0 = { ed b2 [2] df 90 [2] d9 a5 [2] f7 a5 [2] c8 b9 }

  condition:
    any of them
}