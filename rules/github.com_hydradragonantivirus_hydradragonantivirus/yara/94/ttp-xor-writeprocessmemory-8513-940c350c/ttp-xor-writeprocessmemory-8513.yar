rule TTP_XOR_WriteProcessMemory_8513 {
  strings:
    $key_8513 = { d2 61 [2] e0 43 [2] e6 76 [2] c8 76 [2] f7 6a }

  condition:
    any of them
}