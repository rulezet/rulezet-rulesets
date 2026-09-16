rule TTP_XOR_WriteProcessMemory_8725 {
  strings:
    $key_8725 = { d0 57 [2] e2 75 [2] e4 40 [2] ca 40 [2] f5 5c }

  condition:
    any of them
}