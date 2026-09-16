rule TTP_XOR_WriteProcessMemory_9304 {
  strings:
    $key_9304 = { c4 76 [2] f6 54 [2] f0 61 [2] de 61 [2] e1 7d }

  condition:
    any of them
}