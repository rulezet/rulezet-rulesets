rule TTP_XOR_WriteProcessMemory_8373 {
  strings:
    $key_8373 = { d4 01 [2] e6 23 [2] e0 16 [2] ce 16 [2] f1 0a }

  condition:
    any of them
}