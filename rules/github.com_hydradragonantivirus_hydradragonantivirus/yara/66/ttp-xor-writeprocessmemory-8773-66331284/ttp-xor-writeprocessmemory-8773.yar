rule TTP_XOR_WriteProcessMemory_8773 {
  strings:
    $key_8773 = { d0 01 [2] e2 23 [2] e4 16 [2] ca 16 [2] f5 0a }

  condition:
    any of them
}