rule TTP_XOR_WriteProcessMemory_8577 {
  strings:
    $key_8577 = { d2 05 [2] e0 27 [2] e6 12 [2] c8 12 [2] f7 0e }

  condition:
    any of them
}