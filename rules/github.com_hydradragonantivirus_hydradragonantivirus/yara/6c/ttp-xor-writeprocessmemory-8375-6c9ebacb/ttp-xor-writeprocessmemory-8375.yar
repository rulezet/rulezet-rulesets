rule TTP_XOR_WriteProcessMemory_8375 {
  strings:
    $key_8375 = { d4 07 [2] e6 25 [2] e0 10 [2] ce 10 [2] f1 0c }

  condition:
    any of them
}