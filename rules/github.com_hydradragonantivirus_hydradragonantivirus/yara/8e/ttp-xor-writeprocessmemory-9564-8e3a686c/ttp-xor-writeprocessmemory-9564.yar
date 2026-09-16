rule TTP_XOR_WriteProcessMemory_9564 {
  strings:
    $key_9564 = { c2 16 [2] f0 34 [2] f6 01 [2] d8 01 [2] e7 1d }

  condition:
    any of them
}