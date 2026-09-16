rule TTP_XOR_WriteProcessMemory_9367 {
  strings:
    $key_9367 = { c4 15 [2] f6 37 [2] f0 02 [2] de 02 [2] e1 1e }

  condition:
    any of them
}