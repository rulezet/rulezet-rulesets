rule TTP_XOR_WriteProcessMemory_8365 {
  strings:
    $key_8365 = { d4 17 [2] e6 35 [2] e0 00 [2] ce 00 [2] f1 1c }

  condition:
    any of them
}