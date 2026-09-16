rule TTP_XOR_WriteProcessMemory_8552 {
  strings:
    $key_8552 = { d2 20 [2] e0 02 [2] e6 37 [2] c8 37 [2] f7 2b }

  condition:
    any of them
}