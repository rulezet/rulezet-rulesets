rule TTP_XOR_WriteProcessMemory_9543 {
  strings:
    $key_9543 = { c2 31 [2] f0 13 [2] f6 26 [2] d8 26 [2] e7 3a }

  condition:
    any of them
}