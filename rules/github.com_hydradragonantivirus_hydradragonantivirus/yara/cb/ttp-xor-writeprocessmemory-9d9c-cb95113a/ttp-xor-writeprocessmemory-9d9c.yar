rule TTP_XOR_WriteProcessMemory_9d9c {
  strings:
    $key_9d9c = { ca ee [2] f8 cc [2] fe f9 [2] d0 f9 [2] ef e5 }

  condition:
    any of them
}