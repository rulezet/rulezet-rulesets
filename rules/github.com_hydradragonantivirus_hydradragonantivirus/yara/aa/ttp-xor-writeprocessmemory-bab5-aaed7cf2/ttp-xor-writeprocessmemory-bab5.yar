rule TTP_XOR_WriteProcessMemory_bab5 {
  strings:
    $key_bab5 = { ed c7 [2] df e5 [2] d9 d0 [2] f7 d0 [2] c8 cc }

  condition:
    any of them
}