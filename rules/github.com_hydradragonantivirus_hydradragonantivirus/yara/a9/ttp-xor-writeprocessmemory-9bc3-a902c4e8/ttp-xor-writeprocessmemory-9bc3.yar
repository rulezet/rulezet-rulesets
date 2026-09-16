rule TTP_XOR_WriteProcessMemory_9bc3 {
  strings:
    $key_9bc3 = { cc b1 [2] fe 93 [2] f8 a6 [2] d6 a6 [2] e9 ba }

  condition:
    any of them
}