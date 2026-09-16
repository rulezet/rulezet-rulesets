rule TTP_XOR_WriteProcessMemory_8522 {
  strings:
    $key_8522 = { d2 50 [2] e0 72 [2] e6 47 [2] c8 47 [2] f7 5b }

  condition:
    any of them
}