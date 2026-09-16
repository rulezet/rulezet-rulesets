rule TTP_XOR_WriteProcessMemory_8540 {
  strings:
    $key_8540 = { d2 32 [2] e0 10 [2] e6 25 [2] c8 25 [2] f7 39 }

  condition:
    any of them
}