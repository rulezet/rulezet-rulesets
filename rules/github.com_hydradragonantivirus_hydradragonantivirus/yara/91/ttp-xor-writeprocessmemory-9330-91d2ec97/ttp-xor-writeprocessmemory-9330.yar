rule TTP_XOR_WriteProcessMemory_9330 {
  strings:
    $key_9330 = { c4 42 [2] f6 60 [2] f0 55 [2] de 55 [2] e1 49 }

  condition:
    any of them
}