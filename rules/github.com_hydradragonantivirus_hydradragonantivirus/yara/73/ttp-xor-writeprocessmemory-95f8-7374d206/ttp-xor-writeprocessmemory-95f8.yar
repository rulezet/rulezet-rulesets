rule TTP_XOR_WriteProcessMemory_95f8 {
  strings:
    $key_95f8 = { c2 8a [2] f0 a8 [2] f6 9d [2] d8 9d [2] e7 81 }

  condition:
    any of them
}