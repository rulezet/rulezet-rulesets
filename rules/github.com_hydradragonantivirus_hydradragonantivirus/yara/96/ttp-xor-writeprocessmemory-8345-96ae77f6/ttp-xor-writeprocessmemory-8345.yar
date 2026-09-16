rule TTP_XOR_WriteProcessMemory_8345 {
  strings:
    $key_8345 = { d4 37 [2] e6 15 [2] e0 20 [2] ce 20 [2] f1 3c }

  condition:
    any of them
}