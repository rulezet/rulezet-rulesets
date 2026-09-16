rule TTP_XOR_WriteProcessMemory_9317 {
  strings:
    $key_9317 = { c4 65 [2] f6 47 [2] f0 72 [2] de 72 [2] e1 6e }

  condition:
    any of them
}