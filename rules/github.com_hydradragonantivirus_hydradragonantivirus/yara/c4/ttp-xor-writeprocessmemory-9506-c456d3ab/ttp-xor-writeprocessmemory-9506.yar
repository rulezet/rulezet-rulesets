rule TTP_XOR_WriteProcessMemory_9506 {
  strings:
    $key_9506 = { c2 74 [2] f0 56 [2] f6 63 [2] d8 63 [2] e7 7f }

  condition:
    any of them
}