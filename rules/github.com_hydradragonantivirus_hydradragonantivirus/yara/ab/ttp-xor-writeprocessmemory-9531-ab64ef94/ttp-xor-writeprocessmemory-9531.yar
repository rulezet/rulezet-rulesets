rule TTP_XOR_WriteProcessMemory_9531 {
  strings:
    $key_9531 = { c2 43 [2] f0 61 [2] f6 54 [2] d8 54 [2] e7 48 }

  condition:
    any of them
}