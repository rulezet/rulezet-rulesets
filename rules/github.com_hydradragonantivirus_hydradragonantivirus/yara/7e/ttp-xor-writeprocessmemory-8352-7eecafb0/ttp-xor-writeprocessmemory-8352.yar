rule TTP_XOR_WriteProcessMemory_8352 {
  strings:
    $key_8352 = { d4 20 [2] e6 02 [2] e0 37 [2] ce 37 [2] f1 2b }

  condition:
    any of them
}