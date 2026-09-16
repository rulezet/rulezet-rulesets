rule TTP_XOR_WriteProcessMemory_8330 {
  strings:
    $key_8330 = { d4 42 [2] e6 60 [2] e0 55 [2] ce 55 [2] f1 49 }

  condition:
    any of them
}