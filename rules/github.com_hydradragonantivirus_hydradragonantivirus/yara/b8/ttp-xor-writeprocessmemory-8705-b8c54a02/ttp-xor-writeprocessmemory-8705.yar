rule TTP_XOR_WriteProcessMemory_8705 {
  strings:
    $key_8705 = { d0 77 [2] e2 55 [2] e4 60 [2] ca 60 [2] f5 7c }

  condition:
    any of them
}