rule TTP_XOR_WriteProcessMemory_8305 {
  strings:
    $key_8305 = { d4 77 [2] e6 55 [2] e0 60 [2] ce 60 [2] f1 7c }

  condition:
    any of them
}