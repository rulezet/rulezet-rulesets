rule TTP_XOR_WriteProcessMemory_95f9 {
  strings:
    $key_95f9 = { c2 8b [2] f0 a9 [2] f6 9c [2] d8 9c [2] e7 80 }

  condition:
    any of them
}