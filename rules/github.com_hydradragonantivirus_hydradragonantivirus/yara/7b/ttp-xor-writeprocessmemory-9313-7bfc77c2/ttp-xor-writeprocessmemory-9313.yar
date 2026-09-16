rule TTP_XOR_WriteProcessMemory_9313 {
  strings:
    $key_9313 = { c4 61 [2] f6 43 [2] f0 76 [2] de 76 [2] e1 6a }

  condition:
    any of them
}