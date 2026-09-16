rule TTP_XOR_WriteProcessMemory_8507 {
  strings:
    $key_8507 = { d2 75 [2] e0 57 [2] e6 62 [2] c8 62 [2] f7 7e }

  condition:
    any of them
}