rule TTP_XOR_WriteProcessMemory_8331 {
  strings:
    $key_8331 = { d4 43 [2] e6 61 [2] e0 54 [2] ce 54 [2] f1 48 }

  condition:
    any of them
}