rule TTP_XOR_WriteProcessMemory_8343 {
  strings:
    $key_8343 = { d4 31 [2] e6 13 [2] e0 26 [2] ce 26 [2] f1 3a }

  condition:
    any of them
}