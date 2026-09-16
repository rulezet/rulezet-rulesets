rule TTP_XOR_WriteProcessMemory_bab1 {
  strings:
    $key_bab1 = { ed c3 [2] df e1 [2] d9 d4 [2] f7 d4 [2] c8 c8 }

  condition:
    any of them
}