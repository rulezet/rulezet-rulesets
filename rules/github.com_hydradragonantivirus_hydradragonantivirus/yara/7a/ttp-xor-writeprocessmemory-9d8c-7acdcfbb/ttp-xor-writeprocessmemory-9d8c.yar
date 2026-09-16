rule TTP_XOR_WriteProcessMemory_9d8c {
  strings:
    $key_9d8c = { ca fe [2] f8 dc [2] fe e9 [2] d0 e9 [2] ef f5 }

  condition:
    any of them
}