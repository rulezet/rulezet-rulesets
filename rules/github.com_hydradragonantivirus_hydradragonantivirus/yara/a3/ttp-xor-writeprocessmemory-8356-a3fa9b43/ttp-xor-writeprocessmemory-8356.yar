rule TTP_XOR_WriteProcessMemory_8356 {
  strings:
    $key_8356 = { d4 24 [2] e6 06 [2] e0 33 [2] ce 33 [2] f1 2f }

  condition:
    any of them
}