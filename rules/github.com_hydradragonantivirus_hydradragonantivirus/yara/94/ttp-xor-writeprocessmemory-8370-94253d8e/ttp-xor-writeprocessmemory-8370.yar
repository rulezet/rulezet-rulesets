rule TTP_XOR_WriteProcessMemory_8370 {
  strings:
    $key_8370 = { d4 02 [2] e6 20 [2] e0 15 [2] ce 15 [2] f1 09 }

  condition:
    any of them
}