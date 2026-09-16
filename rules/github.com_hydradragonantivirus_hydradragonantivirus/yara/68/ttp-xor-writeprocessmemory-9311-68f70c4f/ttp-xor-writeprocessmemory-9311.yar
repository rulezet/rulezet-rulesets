rule TTP_XOR_WriteProcessMemory_9311 {
  strings:
    $key_9311 = { c4 63 [2] f6 41 [2] f0 74 [2] de 74 [2] e1 68 }

  condition:
    any of them
}