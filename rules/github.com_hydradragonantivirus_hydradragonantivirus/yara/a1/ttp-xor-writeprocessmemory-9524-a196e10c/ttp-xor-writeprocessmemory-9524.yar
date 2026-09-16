rule TTP_XOR_WriteProcessMemory_9524 {
  strings:
    $key_9524 = { c2 56 [2] f0 74 [2] f6 41 [2] d8 41 [2] e7 5d }

  condition:
    any of them
}