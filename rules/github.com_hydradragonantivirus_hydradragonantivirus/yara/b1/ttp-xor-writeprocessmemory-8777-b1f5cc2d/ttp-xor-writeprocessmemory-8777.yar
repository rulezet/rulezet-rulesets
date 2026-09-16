rule TTP_XOR_WriteProcessMemory_8777 {
  strings:
    $key_8777 = { d0 05 [2] e2 27 [2] e4 12 [2] ca 12 [2] f5 0e }

  condition:
    any of them
}