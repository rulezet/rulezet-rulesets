rule TTP_XOR_WriteProcessMemory_bab4 {
  strings:
    $key_bab4 = { ed c6 [2] df e4 [2] d9 d1 [2] f7 d1 [2] c8 cd }

  condition:
    any of them
}