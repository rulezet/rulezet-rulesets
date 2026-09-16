rule TTP_XOR_WriteProcessMemory_8325 {
  strings:
    $key_8325 = { d4 57 [2] e6 75 [2] e0 40 [2] ce 40 [2] f1 5c }

  condition:
    any of them
}