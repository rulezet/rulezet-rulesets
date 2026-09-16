rule TTP_XOR_WriteProcessMemory_bab0 {
  strings:
    $key_bab0 = { ed c2 [2] df e0 [2] d9 d5 [2] f7 d5 [2] c8 c9 }

  condition:
    any of them
}