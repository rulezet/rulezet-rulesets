rule TTP_XOR_WriteProcessMemory_8ab5 {
  strings:
    $key_8ab5 = { dd c7 [2] ef e5 [2] e9 d0 [2] c7 d0 [2] f8 cc }

  condition:
    any of them
}