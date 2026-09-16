rule TTP_XOR_WriteProcessMemory_8539 {
  strings:
    $key_8539 = { d2 4b [2] e0 69 [2] e6 5c [2] c8 5c [2] f7 40 }

  condition:
    any of them
}