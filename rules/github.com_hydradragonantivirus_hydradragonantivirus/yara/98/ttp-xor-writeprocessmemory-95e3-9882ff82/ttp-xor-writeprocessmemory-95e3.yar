rule TTP_XOR_WriteProcessMemory_95e3 {
  strings:
    $key_95e3 = { c2 91 [2] f0 b3 [2] f6 86 [2] d8 86 [2] e7 9a }

  condition:
    any of them
}