rule TTP_XOR_WriteProcessMemory_8374 {
  strings:
    $key_8374 = { d4 06 [2] e6 24 [2] e0 11 [2] ce 11 [2] f1 0d }

  condition:
    any of them
}