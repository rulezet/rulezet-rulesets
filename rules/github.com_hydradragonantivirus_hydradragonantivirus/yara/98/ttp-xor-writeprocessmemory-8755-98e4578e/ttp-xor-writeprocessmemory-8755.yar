rule TTP_XOR_WriteProcessMemory_8755 {
  strings:
    $key_8755 = { d0 27 [2] e2 05 [2] e4 30 [2] ca 30 [2] f5 2c }

  condition:
    any of them
}