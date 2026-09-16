rule TTP_XOR_WriteProcessMemory_9324 {
  strings:
    $key_9324 = { c4 56 [2] f6 74 [2] f0 41 [2] de 41 [2] e1 5d }

  condition:
    any of them
}