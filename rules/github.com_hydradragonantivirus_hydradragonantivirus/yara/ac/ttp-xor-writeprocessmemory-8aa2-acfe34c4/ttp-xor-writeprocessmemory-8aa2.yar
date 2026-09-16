rule TTP_XOR_WriteProcessMemory_8aa2 {
  strings:
    $key_8aa2 = { dd d0 [2] ef f2 [2] e9 c7 [2] c7 c7 [2] f8 db }

  condition:
    any of them
}